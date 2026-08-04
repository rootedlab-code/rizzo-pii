# -*- coding: utf-8 -*-
"""
Entry headless del backend per l'app desktop Tauri.

Avvia SOLO il server Flask in locale: la finestra nativa la apre Tauri (WebView2),
quindi qui NON si apre alcun browser. Pensato per girare come processo figlio (sidecar)
dell'app Tauri, impacchettato con PyInstaller in modalita' windowed (console=False).

In modalita' windowed sys.stdout/sys.stderr sono None: li reindirizziamo su un file di
log PRIMA di importare 'app' (che al caricamento stampa e carica il modello), cosi'
nessun print() fa crashare il processo e i problemi restano diagnosticabili.

Configurazione host/porta, in ordine di precedenza:
  1) env PII_HOST / PII_PORT     -\u003e  passati da Tauri (lib.rs)
  2) config.json                 -\u003e  salvato da Tauri o dall'UI Flask
  3) default 127.0.0.1:5005

Questo entry point **non ha argomenti da riga di comando**: Tauri lancia il sidecar
passando solo delle env (lib.rs, spawn_sidecar). La stesura precedente di questa
docstring prometteva --host/--port, che il codice qui sotto non ha mai letto - e
descriveva la catena di server_config invece del proprio comportamento.

Il resto della configurazione (detector, ingaggio, modello) NON arriva da qui: lo
risolve `app` al proprio import, da env e dai file in config_dir().

NB: la 5000 su macOS e' occupata da AirPlay Receiver (ControlCenter) -\u003e pagina bianca.

Log: config_dir()/backend.log, cioe' %LOCALAPPDATA%\\\\rizzo-pii\\\\ su Windows,
~/Library/Application Support/rizzo-pii/ su macOS, ~/.local/share/rizzo-pii/ su Linux.
Prima si usava LOCALAPPDATA anche fuori da Windows, dove non esiste: il log finiva in
~/rizzo-pii/, cioe' non dove la documentazione e i messaggi di Tauri dicevano.

Codici di uscita riconosciuti da Tauri:
  76 (EX_PROTOCOL) -> porta occupata; lo splash mostra il form di configurazione
  78 (EX_CONFIG)   -> configurazione non utilizzabile (p.es. file di ingaggio rotto)
"""

import os
import sys

# --- log su file (windowed mode -> niente console) ------------------------- #
# La stessa directory della configurazione: prima si usava LOCALAPPDATA anche su Linux
# e macOS, dove non esiste, e il log finiva in ~/rizzo-pii/ mentre la docstring e i
# messaggi di Tauri ne annunciavano un'altra. Un log che non e' dove si dice non e'
# diagnosticabile - ed e' l'unica diagnostica che il sidecar ha, perche' gira windowed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server_config as _sc  # noqa: E402

_logdir = str(_sc.config_dir())
try:
    os.makedirs(_logdir, exist_ok=True)
    _log = open(os.path.join(_logdir, "backend.log"), "w", encoding="utf-8", buffering=1)
    sys.stdout = _log
    sys.stderr = _log
except Exception:
    pass  # se non si puo' loggare, si prosegue comunque

server_config = _sc          # gia' importato sopra per sapere dove scrivere il log

HOST, PORT = server_config.resolve()

# --- pre-check porta PRIMA di caricare il modello (che richiede secondi) --- #
if not server_config.port_available(HOST, PORT):
    print(f"[serve] ERRORE: porta {PORT} occupata su {HOST}")
    sys.exit(server_config.EXIT_PORT_CONFLICT)

# --- pre-check dell'ingaggio, PRIMA di caricare il modello ------------------ #
# Stesso argomento del pre-check della porta: `scope` e' un modulo puro e costa
# millisecondi, mentre l'import di `app` carica 1,2 GB. Senza questo, chi ha un file di
# ingaggio rotto aspetta il caricamento completo per sentirsi dire che un JSON e'
# malformato. Il file viene letto due volte (qui e all'import di app): e' il prezzo per
# non far dipendere serve.py dai moduli pesanti, ed e' un parse di pochi kB.
import scope as scope_mod  # noqa: E402

try:
    scope_mod.load_scope()
except scope_mod.ScopeError as _exc:
    print(f"[serve] ERRORE nel file di ingaggio ({scope_mod.scope_path()}): {_exc}")
    sys.exit(server_config.EXIT_BAD_CONFIG)

# l'import carica il modello (puo' richiedere alcuni secondi)
import app as app_mod   # noqa: E402
from app import app  # noqa: E402

if __name__ == "__main__":
    # Nel sidecar windowed backend.log e' l'UNICA diagnostica: senza questa riga la
    # domanda "perche' i detector non sono attivi?" non ha risposta.
    print(f"[serve] modello: {app_mod.MODEL_DIR}")
    print(f"[serve] detector attivi: core"
          + (f" + {', '.join(app_mod.ACTIVE_PACKS)}" if app_mod.ACTIVE_PACKS else ""))
    print(f"[serve] ingaggio: {scope_mod.scope_path() or 'nessuno'}")
    print(f"[serve] avvio server su {HOST}:{PORT}")
    try:
        app.run(host=HOST, port=PORT, threaded=True)
    except OSError as e:
        # sicurezza extra: se il bind fallisce nonostante il pre-check (race condition)
        print(f"[serve] ERRORE bind: {e}")
        sys.exit(server_config.EXIT_PORT_CONFLICT)
