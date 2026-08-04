# Piano — rendere usabili dall'app desktop le capacità di sicurezza

**Stato: APPROVATO. Fasi 0 e 1 FATTE il 2026-08-04.** Fasi 2-4 da fare.
Redatto il 2026-08-04 da tre analisi indipendenti in contesto separato, con le
affermazioni decisive **riverificate a mano** (§8).

| fase | stato | commit |
|---|---|---|
| 0 — sbloccare il build | ✅ fatta | `c8f712b`, `72885c9`, `76bac96` |
| 1 — il modello giusto nel pacchetto | ✅ fatta | `da0a098` |
| 2 — detector accendibili, profilo onesto | da fare | — |
| 3 — cablaggio della configurazione | da fare | — |
| 4 — scope dall'app (richiede Rust) | da fare | — |

Difetti chiusi: **D1** (`PII_MODEL_DIR` codice morto) e **D2** (build rotto).
Difetto trovato durante il lavoro e **non** risolto: **D9** — la suite ha una
dipendenza dall'ordine preesistente (`test_generate_cyber_pii::test_registering_does_not_break_the_upstream_slots`
fallisce se i test girano in ordine inverso). Verificato preesistente escludendo i
file nuovi. Fuori dal piano, da decidere a parte.

Follow-up aperto: `create_mock_model.py` genera ancora un modello finto in
`models/rizzo-pii-0.3B-v1.2.0/`, il path che gli spec hanno smesso di usare.

---

## 1. Obiettivo

Oggi `rizzo-pii-security` esiste come repository, non come prodotto: chi installa l'app
desktop ottiene il modello sbagliato, con i detector di sicurezza spenti e senza alcun
modo di accenderli. Le tre capacità costruite ad agosto — detector cyber, policy per
ruolo, scope d'ingaggio — sono raggiungibili **solo da terminale**, con variabili
d'ambiente e un file JSON scritto a mano.

Obiettivo: che un utente che installa l'app ottenga il modello che ha superato il
criterio, possa accendere i detector di sicurezza da un'interfaccia, e non veda mai
un'opzione che promette qualcosa che il programma non fa.

## 2. Vincoli

1. **`config.json` non può ospitare chiavi nuove.** Lo riscrivono per intero **due**
   scrittori distruttivi: `tauri/src-tauri/src/lib.rs:89-95` e
   `server_config.save_config()` (`server_config.py:57-63`), quest'ultimo raggiungibile
   da `POST /config` (`app.py:579`), cioè dal modale ⚙️ di qualunque utente.
2. **`GET /scope` non acquisisce un POST e non espone valori** (`app.py:621-636`). È una
   decisione di sicurezza: quel file contiene gli IP del cliente e gli IOC
   dell'avversario.
3. **L'ordine `enable_packs()` → `known_tags()` → risoluzione della policy non è
   negoziabile.** Invertirlo fa scartare `keep_tags: IP` come tag inesistente
   (`app.py:1434-1435` lo documenta già per il ramo CLI).
4. **Il modello non si sostituisce a caldo.** `nlp` è costruito all'import
   (`app.py:82-88`), letto dentro `analyze()` (`app.py:333`), con Flask in
   `threaded=True`. Ricaricare 1,2 GB su CPU sono decine di secondi con l'interfaccia
   ferma.
5. **La promessa «100% in locale»** (badge nella UI, `app.py:897`) esclude qualunque
   download del modello al primo avvio.
6. **Compatibilità dell'handshake Tauri**: `GET /config` deve continuare a contenere
   `config_path`, che `lib.rs:134` usa per riconoscere il proprio backend.
7. La suite gira col **python di sistema** (`python3 -m unittest discover -s tests`,
   361 test verdi). Il `.venv` della repo è per il training e non va usato per i test.

## 3. Stato attuale

### 3.1 Ciò che l'app impacchettata riceve

Tauri lancia il sidecar con **due sole variabili**, `PII_HOST` e `PII_PORT`
(`lib.rs:151-156`), da **due punti di chiamata** distinti (`lib.rs:279` al retry,
`lib.rs:366` all'avvio). Il sidecar è `serve.py`, che importa `app` (`serve.py:49`) e
quindi **non esegue mai** il blocco `__main__` dove vivono `--detectors` e
`--scope-file` (`app.py:1417-1471`).

| capacità | dove si accende oggi | nell'app |
|---|---|---|
| policy (profilo, tag in chiaro) | `GET/POST /policy` | ✅ nel modale, si applica subito |
| detector cyber | `PII_DETECTORS` all'import (`app.py:239`) o `--detectors` | ❌ irraggiungibile |
| scope d'ingaggio | `PII_SCOPE_FILE` (`scope.py:345-352`) | ❌ irraggiungibile |
| scelta del modello | `PII_MODEL_DIR` (`app.py:56`) | ❌ **codice morto**, vedi 3.2 |

### 3.2 Otto difetti preesistenti, tutti verificati

| # | difetto | evidenza |
|---|---|---|
| D1 | **`PII_MODEL_DIR` è irraggiungibile in un pacchetto**: il ramo `_MEIPASS` viene prima | `app.py:54-57` |
| D2 | **Il build è già rotto**: quattro path a mano verso `models/rizzo-pii-0.3B-v1.2.0`, che non esiste | `build.spec:16`, `build_sidecar.spec:17`, `build_linux.sh:26`, `build_mac.sh:31` |
| D3 | **`security-report` è un placebo a pacchetto spento**: `resolve_roles()` ritorna `{}`, identico a `full`, con un warning che finisce in un log che nessuno apre | riprodotto, §8 |
| D4 | `load_config()` non ha la guardia `isinstance(dict)` che `policy.load_file()` ha: un `config.json` con `[1,2]` uccide il sidecar | `server_config.py:46-54` vs `policy.py:110-120` |
| D5 | `enable_packs()` ignora **in silenzio** i pacchetti sconosciuti (solo un `print`). Un `cyver` di troppo spegne i detector e **lascia gli IOC in chiaro** | `app.py:225-228` |
| D6 | Uno scope rotto esce con `1`, e Tauri traduce qualunque codice ≠76 in «il backend si è chiuso inaspettatamente» | `app.py:284-286`, `lib.rs:199-212` |
| D7 | La docstring di `serve.py` promette argomenti CLI che non esistono | `serve.py:13-18` vs `:41` |
| D8 | **Il modale può già cancellare `keep_tags` dal disco**: avviato senza pacchetto, aprire ⚙️ e premere Salva riscrive `policy.json` senza i tag fuori tassonomia | `app.py:1378` → `:1400` → `:613` |

### 3.3 Il fatto che riordina le priorità

I due checkpoint hanno **`id2label` identico, 44 etichette**: la sostituzione è drop-in,
non tocca `known_tags()` né la policy. Il modello di sicurezza **ha già superato il
criterio pre-registrato** (`docs/CRITERIO.md`): recall 0.737 → 0.808 sulla riserva,
regole A, B e C superate, zero tag in regressione — e migliora **anche sul dominio
legale**, che è il caso d'uso in produzione. La cautela della scheda sulla
frammentazione è chiusa da `_fuse_adjacent` (misurata oggi: 1,8% contro 0,3%, riparata a
valle dalla fusione).

Il lavoro caro è già stato fatto e pagato con l'unico campione cieco rimasto. **Manca la
riga che lo consegna agli utenti.**

## 4. Stato di arrivo

- L'app impacchettata carica il checkpoint che ha superato il criterio, e sa dire quale
  sta caricando.
- I detector di sicurezza si accendono e si spengono dal modale ⚙️, con la policy
  ricalcolata nell'ordine corretto e senza corse critiche.
- Il profilo `security-report` o funziona, o dice perché non può.
- Lo scope d'ingaggio si sceglie da un dialogo nativo del sistema operativo, mai da una
  form web.
- I quattro path del modello diventano uno.

## 5. Piano per passi

**Ogni fase è rilasciabile da sola e lascia la suite verde.** Le fasi 0-2 sono
**solo-Python**: si spediscono ricostruendo il sidecar, senza ricompilare Rust né
rinotarizzare su macOS.

### Fase 0 — sbloccare il build (prerequisito di qualunque rilascio)

| passo | file | intento | prova |
|---|---|---|---|
| 0.1 | `build.spec`, `build_sidecar.spec`, `build_linux.sh`, `build_mac.sh` | un solo punto di verità: `PII_BUILD_MODEL`, default `models/rizzo-pii-0.3B-security`, con `assert` sull'esistenza | `tests/test_build_model.py`: i quattro file leggono la stessa variabile |
| 0.2 | `src/app/app.py:54-70` | estrarre la risoluzione in `server_config.resolve_model_dir()`, **con `PII_MODEL_DIR` prima di `_MEIPASS`** (chiude D1) e ricaduta sul modello impacchettato se l'override è rotto | test puri sull'ordine di precedenza |
| 0.3 | `src/training/test_pii.py:39-58` | delegare allo stesso risolutore: oggi è un gemello non sorvegliato con regole diverse | `test_the_app_and_the_cli_resolve_the_same_directory` |

*Rollback:* i passi 0.1-0.3 sono indipendenti e revertibili singolarmente.

### Fase 1 — il modello giusto nel pacchetto

| passo | file | intento | prova |
|---|---|---|---|
| 1.1 | spec di build | `model_info.json` accanto al modello (nome, id HF, sha256) | — |
| 1.2 | `src/app/app.py` | `GET /model` che lo espone, riga di sola lettura nel modale | test d'endpoint |
| 1.3 | `docs/CHANGELOG.md` | dichiarare lo swap **e** che non resta alcun campione cieco per il prossimo | — |

*Perché serve il timbro:* con due checkpoint da 1,2 GB e lo stesso `id2label`, da
un'app in esecuzione **è impossibile sapere quale sta girando** (dentro un pacchetto
`MODEL_DIR` è sempre `.../pii_model`). È la forma di difetto della tabella dei gemelli:
l'artefatto contro ciò che dichiara di essere.

### Fase 2 — detector accendibili, e un profilo che non mente

| passo | file | intento | prova |
|---|---|---|---|
| 2.1 | `src/app/app.py:222-236` | `enable_packs` costruisce in locali e **pubblica una volta sola** come tuple: oggi assegna e poi muta con `+=`, e un lettore può vedere una lista a metà | `test_enable_packs_never_publishes_a_half_built_list` |
| 2.2 | `src/app/app.py` | snapshot per richiesta in `analyze()`: `POLICY` è riletta **dentro** il ciclo (`:434`) e di nuovo nel report (`:491`), `ACTIVE_KEEP` due volte (`:248`, `:251`) | `test_analyze_reports_the_policy_it_actually_applied` |
| 2.3 | `src/app/app.py` | `GET/POST /detectors` sul modello di `/policy`; validazione **nell'endpoint** (400 sui nomi ignoti, chiude D5); `threading.Lock` sui soli scrittori | `TestDetectorsEndpoint` |
| 2.4 | `src/app/app.py` | ordine obbligato: valida → `enable_packs` → `known_tags()` → ricostruisci la policy **dallo stato in esecuzione**, non da `load_policy()` (che resusciterebbe `PII_KEEP_TAGS`); ritorna `dropped_tags` | `TestRuntimeSwitchKeepsThePolicyCoherent` |
| 2.5 | `src/app/policy.py` | `PROFILE_REQUIRES`; `save_file()` preserva la chiave `detectors` come già fa con `keep_roles` | `test_saving_the_policy_does_not_erase_the_detectors` |
| 2.6 | `src/app/app.py` | il profilo **accende i pacchetti che dichiara**; `GET/POST /policy` espongono `requires` e `unmet` | `TestSecurityReportProfileIsHonest`, con `setUp` **a pacchetti spenti** |
| 2.7 | UI | checkbox «Rilevatori aggiuntivi», avviso ambra quando `unmet` contiene `scope`, etichetta del profilo costruita da `profile_roles`; `POST /detectors` **prima** di `POST /policy` | — |

*Rollback:* 2.1 e 2.2 sono migliorie indipendenti che restano valide anche annullando il resto.

### Fase 3 — il cablaggio della configurazione

| passo | file | intento | prova |
|---|---|---|---|
| 3.1 | `src/app/server_config.py` | guardia `isinstance(dict)` in `load_config()` (chiude D4); `EXIT_BAD_CONFIG = 78` | `test_load_config_ignores_a_json_that_is_not_an_object` |
| 3.2 | `src/app/scope.py:345-352` | quarto anello: CLI > env > **file puntatore** > nessuno. Python **legge e basta**: nessuna funzione scrive quel file | `tests/test_scope_pointer.py` |
| 3.3 | `src/app/app.py`, `serve.py` | scope rotto → uscita 78; riga di log con la configurazione risolta (nel sidecar `backend.log` è l'unica diagnostica) | — |
| 3.4 | `serve.py`, `desktop_app.py` | correggere le docstring che promettono CLI inesistenti (D7) | — |

### Fase 4 — lo scope dall'app (richiede Rust)

| passo | file | intento |
|---|---|---|
| 4.1 | `lib.rs` | voce di menu nativa «Ingaggio → Scegli file…», `tauri-plugin-dialog` invocato **da Rust**; scrive il puntatore, aggiunge `PII_SCOPE_FILE` a `spawn_sidecar` (**entrambi** i call site) e riusa `retry_backend` |
| 4.2 | `lib.rs` | ramo per il codice 78 nello splash: «Configurazione non valida» + «Scegli un altro file» / «Continua senza ingaggio» (chiude D6) |
| 4.3 | UI | blocco scope nel modale: **basename** del file (il percorso completo nomina il cliente e i modali finiscono negli screenshot), conteggi per ruolo, stato del contesto — riletti sempre da `GET /scope`, mai da ciò che l'utente ha appena scelto |

## 6. Dove le tre analisi non erano d'accordo, e come l'ho sciolta

Tre proposte diverse su **dove persistere** le impostazioni nuove. La risoluzione non è
un compromesso: ogni destinazione è scelta da una proprietà diversa del dato.

| dato | destinazione | perché |
|---|---|---|
| `detectors` | **`policy.json`** | è modificabile a runtime, quindi non appartiene alle impostazioni d'avvio; ed è concettualmente adiacente alla policy («cosa cerco» accanto a «cosa ne faccio»). `save_file()` ha già la disciplina di preservare le chiavi estranee per `keep_roles` |
| `scope_file` | **file puntatore separato**, mai scritto da Python | il percorso può entrare, ma non dalla webview: un `POST` lo renderebbe un oracolo di lettura del filesystem, e `ScopeError` mette **un valore vero preso dal file** nel messaggio d'errore (`scope.py:239-242`) |
| `model_dir` | **variabile di build + env**, nessun file | il modello non si sostituisce a caldo (vincolo 4): una configurazione persistente prometterebbe una scelta che il programma non può onorare |

## 7. Rischi

1. **Il cambio di modello cambia i risultati per l'utenza legale esistente.** Misurato e
   nella direzione giusta (162 PII in chiaro in meno su 2.279), ma è un cambiamento
   silenzioso: va nel changelog e nel timbro del modello, non scoperto.
2. **Nessun campione cieco resta.** La riserva è spesa. Questo swap è coperto dal
   criterio; il **prossimo** richiederà un insieme da una fonte diversa.
3. **Simone sta per rilasciare una versione nuova del checkpoint di partenza.** Il
   nostro fine-tuning ne deriva: quando esce, la ricetta va rifatta (~26 minuti su L4) e
   i confronti rimisurati. Non blocca nulla, ma va messo in conto.
4. **Stato appiccicoso dei pacchetti**: chi prova `security-report` e torna a `clinical`
   resta con `cyber` acceso. Mitigato dalla regola dell'unione ricalcolata a ogni POST e
   dalla riga «Detector attivati dal profilo».
5. **Persistenza del puntatore fra ingaggi**: la sessione dopo lavora sul cliente
   precedente. È il rischio che `scope.py:345-352` evitava rinunciando a un default.
   Mitigato dallo stato sempre visibile nel modale e dal «Rimuovi» a un clic.
6. **Superficie Rust nuova** (fase 4): tre piattaforme da ricompilare, firmare e
   notarizzare.
7. **D8 non è causato da questo lavoro ma ci passa accanto**: chi tocca `policy_post()`
   deve decidere se preservare i tag fuori tassonomia invece di lasciarli cadere.

## 8. Cosa è stato verificato a mano

Le analisi sono state prodotte in contesto separato; queste affermazioni sono state
riverificate direttamente prima di scrivere il piano.

| affermazione | esito |
|---|---|
| `PII_MODEL_DIR` inerte nel pacchetto (`_MEIPASS` vince) | ✅ `app.py:54-57` |
| Due scrittori distruttivi di `config.json` | ✅ `lib.rs:89-95` + `server_config.py:57-63` ← `app.py:579` |
| Il build punta a una directory inesistente | ✅ quattro file, `models/` contiene solo `-base` e `-security` |
| `load_config()` senza guardia `isinstance` | ✅ contro `policy.load_file()` che ce l'ha |
| **`security-report` = `full` a pacchetto spento** | ✅ **riprodotto**: `resolve_roles()` → `{}` |
| `enable_packs` pubblica e poi muta con `+=` | ✅ `app.py:230-235` |
| I due checkpoint sono intercambiabili | ✅ `id2label` identico, 44 etichette |
| Il modello di sicurezza non ha `special_tokens_map.json` | ✅ vero, **ma si carica lo stesso**: già usato oggi su 1.000 righe |
| `test_endpoints_roles.py` verde per il motivo sbagliato | ✅ `setUp:66` forza `enable_packs(["cyber"])` |

## 9. Fuori scope

- Impacchettare **due** modelli e sceglierli a runtime: +1,23 GB per piattaforma, una
  corsa critica su `nlp`, e nessuna capacità che il criterio non abbia già risolto.
- Scaricare il modello al primo avvio: distrugge la promessa «100% in locale».
- Un `POST /scope`, in qualunque forma.
- Rendere non distruttivi i due scrittori di `config.json`: possibile, ma non retroattivo
  sui bundle già installati.
- Riaddestrare sul checkpoint nuovo di Simone: dipende dal suo rilascio.
- Sistemare la deriva dei nomi in `models/` (`-base`/`-security` contro il glob `-v*`).
- D8 (il modale che cancella `keep_tags`): trovato, documentato, non risolto qui.
- La voce di denylist che intercetta le chiavi AWS: decisione separata, già discussa.

## 10. Ordine raccomandato, e perché differisce dalla richiesta

La richiesta diceva «punti 1 e 2, e il resto». **Raccomando di invertire: il modello
per primo.**

- **Sforzo minore di tutti**: due spec, due script, un ordine di righe, una funzione
  estratta, un file di test. Nessuna UI, nessun concetto nuovo, nessun Rust.
- **Beneficio maggiore di tutti**: +0,071 di recall su campione cieco, 162 PII in chiaro
  in meno ogni 2.279, per **il 100% degli utenti su ogni documento**, senza che nessuno
  debba imparare o configurare niente. È l'unico dei tre che migliora la promessa
  centrale del prodotto per chi non saprà mai cosa sia uno scope.
- **Va toccato comunque**: il build è rotto oggi (D2), quindi quei file si aprono in
  ogni caso.
- **La decisione è già stata presa e pagata.** Non consegnarla significa aver speso
  l'ultimo campione cieco per un risultato che nessun utente riceve.

Il cablaggio (punto 1) si semplifica dopo la fase 0, perché l'ordine `_MEIPASS` è già
sistemato. Lo scope (fase 4) resta per ultimo: è il più caro, tocca tre piattaforme, e
prima delle fasi 1-2 servirebbe un pubblico che non esiste — senza il profilo onesto non
agirebbe, e senza il modello giusto leggerebbe quei documenti con il checkpoint sbagliato.
