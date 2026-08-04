# -*- coding: utf-8 -*-
"""
Configurazione host/porta del server Flask (condivisa tra tutti gli entry point).

Risoluzione con precedenza:  CLI args  >  env vars  >  config.json  >  default.

Il file config.json e' condiviso con l'app Tauri (che lo legge/scrive dal lato Rust
e passa host/porta al sidecar via env PII_HOST/PII_PORT):

  Windows:  %LOCALAPPDATA%\\rizzo-pii\\config.json
  Linux:    ~/.local/share/rizzo-pii/config.json
  macOS:    ~/Library/Application Support/rizzo-pii/config.json

Formato:  {"host": "127.0.0.1", "port": 5005}

Il codice di uscita 76 (EX_PROTOCOL) segnala "porta occupata" ed e' riconosciuto
dall'app Tauri per mostrare il form di configurazione nello splash.
"""

import json
import os
import re
import socket
import sys
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5005
EXIT_PORT_CONFLICT = 76  # riconosciuto da Tauri (lib.rs) come "porta occupata"
# EX_CONFIG di sysexits.h: "la configurazione indicata non e' utilizzabile". Distinto
# dal 76 perche' la cura e' diversa - li' si cambia porta, qui si cambia un file - e
# perche' oggi uno scope rotto esce con 1, che Tauri traduce in "il backend si e' chiuso
# inaspettatamente": un messaggio che non aiuta a capire quale file rileggere.
EXIT_BAD_CONFIG = 78

# Nome con cui il modello viene impacchettato dentro l'eseguibile (vedi build.spec).
BUNDLED_MODEL_NAME = "pii_model"

# Puntatore all'ingaggio in corso: contiene un PERCORSO, mai dei valori. Sta in un file
# suo e non in config.json perche' quest'ultimo e' riscritto per intero da Tauri e da
# POST /config, che cancellerebbero la chiave. E non si chiama scope.json di proposito:
# nessuno deve poter credere che basti copiarci dentro il file d'ingaggio.
ENGAGEMENT_FILENAME = "engagement.json"


def config_dir() -> Path:
    """Directory di configurazione (platform-specific, coerente con serve.py e Tauri)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "rizzo-pii"


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> dict:
    """Legge config.json; ritorna {} se mancante, corrotto o non un oggetto.

    La guardia `isinstance(dict)` non e' pedanteria: `[1, 2]` e' JSON valido, quindi
    senza di essa `resolve()` chiamerebbe `.get()` su una lista e il sidecar morirebbe
    prima che Flask apra la porta — con l'app desktop che mostra solo "il backend si e'
    chiuso inaspettatamente". `policy.load_file()` la guardia ce l'aveva gia'."""
    p = config_path()
    if p.exists():
        try:
            data = json.loads(p.read_text("utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(host: str, port: int):
    """Scrive config.json (crea la directory se necessario)."""
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(
        json.dumps({"host": host, "port": port}, indent=2), "utf-8"
    )


def resolve(cli_host=None, cli_port=None):
    """Risolve host/porta con la catena: CLI > env > config.json > default.

    Ritorna (host: str, port: int).
    """
    cfg = load_config()
    host = cli_host or os.environ.get("PII_HOST") or cfg.get("host") or DEFAULT_HOST
    port = cli_port or os.environ.get("PII_PORT") or cfg.get("port") or DEFAULT_PORT
    return str(host), int(port)


def engagement_path() -> Path:
    return config_dir() / ENGAGEMENT_FILENAME


def saved_scope_file():
    """Il percorso del file d'ingaggio salvato, o None.

    **Il lato Python legge e basta**: qui non esiste, e non deve esistere, una funzione
    che scriva questo file. Lo scrive il dialogo nativo del sistema operativo (fase 4),
    mai una form web — `GET /scope` non ha un POST proprio perche' quel file contiene
    gli IP del cliente e gli indicatori dell'avversario.

    Un puntatore ASSENTE significa "nessun ingaggio configurato", che e' il
    comportamento storico. Un puntatore presente ma illeggibile e' un'altra cosa e la
    decide chi chiama: qui si ritorna comunque None, e `scope.py` alza ScopeError."""
    p = engagement_path()
    if not p.is_file():
        return None
    try:
        dati = json.loads(p.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(dati, dict):
        return None
    valore = dati.get("scope_file")
    return str(valore) if valore else None


def _is_model_dir(path) -> bool:
    """Una directory e' un checkpoint se contiene config.json.

    Non basta che esista: puntare il modello a una cartella vuota fa fallire il
    caricamento secondi dopo, dentro transformers, con un errore che non nomina la
    variabile sbagliata."""
    return path is not None and Path(path).is_dir() and (Path(path) / "config.json").is_file()


def _newest_versioned(models_root: Path):
    """L'ultima directory rizzo-pii-0.3B-vX.Y.Z, per numero di versione e non per nome.

    Ordinare per stringa metterebbe la v10 prima della v9."""
    versioned = [p for p in models_root.glob("rizzo-pii-0.3B-v*") if p.is_dir()]
    if not versioned:
        return None
    return max(versioned, key=lambda p: tuple(
        int(x) for x in re.search(r"-v([0-9][0-9.]*)$", p.name).group(1).split(".")))


def resolve_model_dir(override=None, bundled=None, models_root=None,
                      pinned_version=None, warn=None) -> str:
    """Quale checkpoint caricare: override esplicito > modello impacchettato > sviluppo.

    **L'override viene per primo, e questa e' la correzione.** Prima l'ordine era
    invertito: dentro l'eseguibile `sys._MEIPASS` esiste sempre, quindi il ramo
    PII_MODEL_DIR era irraggiungibile e chi installava l'app non poteva puntarla a un
    altro checkpoint nemmeno sapendo cosa stava facendo. Il modello impacchettato e' un
    default, non un lucchetto.

    Un override rotto **non e' fatale**: si avvisa e si ricade sul modello impacchettato.
    Farlo morire qui ucciderebbe il sidecar prima ancora che Flask apra la porta, e
    l'app desktop mostrerebbe solo "il backend si e' chiuso inaspettatamente" — un
    messaggio che non aiuta a trovare una variabile d'ambiente stantia.

    In sviluppo: versione fissata > ultima versionata > rizzo-pii-0.3B > legacy.
    """
    if override:
        if _is_model_dir(override):
            return str(override)
        (warn or print)(
            f"ATTENZIONE: PII_MODEL_DIR={override} non e' un checkpoint "
            f"(manca la directory o il suo config.json). Uso il modello predefinito.")
    if bundled:
        return str(bundled)
    models_root = Path(models_root)
    pinned = models_root / f"rizzo-pii-0.3B-v{pinned_version}" if pinned_version else None
    if pinned is not None and pinned.is_dir():
        return str(pinned)
    newest = _newest_versioned(models_root)
    if newest is not None:
        return str(newest)
    prod = models_root / "rizzo-pii-0.3B"
    return str(prod if prod.exists() else models_root / "pii_model_legacy")


def port_available(host: str, port: int) -> bool:
    """True se la porta e' libera (tenta un bind effimero)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False
