# Gemelli — le coppie che devono coincidere, e chi le sorveglia

Quasi ogni difetto costoso di questo lavoro è stato **lo stesso difetto**: due cose
che dovrebbero coincidere sono divergute, e nessuno le confrontava. Non producono
errori: producono numeri sbagliati, che è peggio, perché ci si costruisce sopra.

Una riga per coppia. Una riga senza test è un debito dichiarato, e si vede.

| # | gemelli | sorvegliato da | stato |
|---|---|---|---|
| 1 | `TAG_MAP`/`DROP_TYPES` in `train_pii.py` ↔ copia in `evaluate_entities.py` | `test_evaluation.py::test_the_copied_tag_map_matches_the_training_one` (rilegge il sorgente con `ast`) | ✅ |
| 2 | rete regex nella valutazione ↔ `app.ACTIVE_DETECTORS` in produzione | `_regex_candidates()` usa direttamente `app`, non una copia | ✅ |
| 3 | risoluzione delle sovrapposizioni in valutazione ↔ `_merge()` dell'app | `test_evaluation.py::test_merging_removes_the_domain_nested_in_a_url` | ✅ |
| 4 | chunking in predizione ↔ `MAX_WORDS`/`OVERLAP` dell'app | costanti copiate in `predict_entities.py` — **nessun test** | ⚠️ |
| 5 | `--limit` in predizione ↔ `--limit` in valutazione | guardia esplicita: righe diverse → esce con errore | ✅ |
| 6 | tassonomia del gold ↔ tassonomia che il modello produce | `--normalize` applica `TAG_MAP`; senza, i nomi segnano recall 0 | ✅ |
| 7 | ordine dei `set` fra due processi ↔ risultato della misura | chiave di ordinamento totale + `test_evaluation.py::TestDeterminism` | ✅ |
| 8 | template dello split `train` ↔ template dello split `eval` | `test_evaluation.py::TestTemplateSplit`, e verifica sugli **scheletri** | ✅ |
| 9 | intervalli di valori in `train` ↔ in `eval` | `test_evaluation.py::TestValuePools` | ✅ |
| 10 | etichette del training ↔ `label2id` del modello | `test_finetune_security.py::TestBioRemapping` | ✅ |
| 11 | ambiente locale ↔ ambiente del pod | `preflight.py` confronta le versioni — **da eseguire su entrambi** | ⚠️ |
| 12 | dataset misurato ↔ dataset addestrato | manifesto sha256 in `preflight.py` — il meccanismo è testato, il confronto del manifesto no | ⚠️ |
| 13 | ciò che il dataset dichiara di insegnare ↔ ciò su cui il training gira | `test_finetune_security.py::TestAllOhRowsAreKept` | ✅ |
| 14 | test congelato ↔ la sua impronta depositata | `preflight.py::verifica_impronta` + `test_preflight.py::TestFrozenFingerprint` | ✅ |
| 15 | leve della riga di comando ↔ `finetune.json` | `scheda_corsa()` parte da `vars(args)`: nessuna leva può mancare **per costruzione**, e `TestRunRecord` lo sorveglia | ✅ |
| 16 | parametri che `--freeze-encoder` dichiara ↔ quelli che aggancia | `test_finetune_security.py::TestFreezeEncoder` asserisce l'insieme **esatto** | ✅ |
| 17 | stub di torch di un file di test ↔ stub degli altri file | `_install_stubs()` aumenta il modulo già presente invece di sostituirlo | ✅ |
| 18 | stratificazione del pool di ripasso ↔ campione che la sonda ne estrae | `head -1000` sul pool: **nessun test**, e la procedura è stata corretta a mano | ⚠️ |
| 19 | numeri registrati ↔ scala dell'esperimento che li ha prodotti | i numeri della sonda e quelli del run pieno vivevano nella stessa tabella — **nessun test** | ⚠️ |
| 20 | leva tarata sulla sonda ↔ leva che agisce davvero nella corsa piena | `quante_di_ripasso()` distingue righe *richieste* e *usate*, e il training avvisa quando il pool satura; `test_finetune_security.py::TestRehearsalSaturation` | ✅ |
| 21 | fusione delle entità adiacenti in **valutazione** ↔ merge dell'**app** | `_fuse_adjacent()` allinea l'app a `normalize_entities()`; `test_analyze_policy.py::TestAdjacentSpansAreFused` | ✅ |
| 22 | popolazione su cui il numero è misurato ↔ popolazione d'uso | `TIME` 0.950 sul congelato e 0 su 9 su un documento vero — **nessun test**, si trova solo usando il tool | ⚠️ |
| 23 | testo su cui si MISURA ↔ testo che esiste in produzione | `from_bio()` riunisce i WordPiece; `test_evaluation.py::TestWordPieceRejoin`. Resta la spaziatura attorno alla punteggiatura: **approssimata, non reale** | ⚠️ |

## I difetti che queste righe hanno già pagato

Ognuna di queste è nata da un numero sbagliato realmente prodotto, non da un timore.

- **#2** — misuravo `detectors_cyber` invece della rete attiva dell'app. `CF` risultava
  **0.018** contro 1.000 reale: stavo per riportare che il modello del progetto è rotto
  sui codici fiscali.
- **#3** — senza `_merge()`, i domini annidati nelle URL contavano come 457 falsi
  positivi. `DOMAIN` precision 0.814 invece di 1.000.
- **#6** — il gold ha `GIVENNAME`+`SURNAME`, il modello produce `FULLNAME`: senza
  rimappare, `FULLNAME` segnava recall **0.000 con 549 falsi positivi**, cioè le
  entità venivano trovate e contate come sbagliate.
- **#7** — la stessa misura sullo stesso file dava 0.817, 0.819, 0.822. `Entity`
  contiene una stringa, l'ordine dei `set` dipende dall'hash randomizzato per processo,
  e la fusione delle entità adiacenti cambiava di conseguenza.
- **#5** — 2.000 righe predette confrontate con 7.000 di gold. Qui la guardia c'era già
  e ha fermato tutto: è l'unico caso in cui il gemello è stato colto sul fatto.
- **#13** — `build_dataset()` scartava le righe interamente `O` con il commento «non
  insegnano nulla». Sono **2.980, il 15,8%** del corpus bilanciato, e sono gli 8
  template su 27 scritti apposta senza PII per insegnare che un indirizzo IP, un hash
  e un identificativo cloud sono `O`. Cioè per chiudere la seconda delle due lacune
  che il fine-tuning esiste per chiudere: le ~2.700 entità inventate su stringhe
  tecniche. Si stava addestrando contro l'obiettivo dichiarato, e nessun numero lo
  mostrava perché il training non fallisce, riesce su meno dati.
- **#16** — `--freeze-encoder` diceva «addestra la testa di classificazione» e
  agganciava il solo `classifier`: **33.836 parametri su 307 milioni, lo 0,011%**.
  `head.dense` e `head.norm` — che sono la testa quanto la proiezione finale —
  restavano congelati. La guardia che c'era coglieva il caso «zero parametri», non
  quello «un decimo dei parametri», che è quello che sarebbe successo.
- **#16, seconda volta** — la correzione passava `model.named_parameters()`, cioè un
  **generatore**, a una funzione che lo scorre una volta per prefisso: `head.` lo
  esauriva e `classifier.` risultava orfano. I test non lo vedevano perché gli
  passavano una lista. Il gemello era fra la forma dell'input nel test e quella
  nell'uso, ed è la ragione per cui ora c'è un test che passa un generatore.
- **#17** — il primo file di test che registra uno stub di `torch` vince, perché tutti
  usano `setdefault`. Il mio arrivava dopo, il suo `torch.utils` non veniva mai
  installato, e tre test fallivano **solo dentro la suite completa** — verdi da soli.
- **#18, il più caro di tutti** — la sonda prendeva il ripasso da `head -1000` del
  pool. In quelle prime 1000 righe ci sono **zero** righe con `CATASTO`, zero con
  `DOCID`, zero con `TARGA`; il pool intero ne ha 682, 1.556 e 424. Il ripasso
  stratificato esiste per coprire i tag assenti dai dati nuovi, e `stratified_rehearsal`
  costruisce quell'elenco **dal pool**: un tag assente dal pool non risultava scoperto,
  risultava *inesistente*. Con il pool intero i tag da proteggere passano da 6 a **11**.
  Per settimane la sonda ha bocciato ricette sul crollo di `CATASTO` — un crollo che il
  suo stesso campione rendeva inevitabile in ogni configurazione. Il troncamento serviva
  a rendere veloce la sonda e non serviva a niente: il ripasso estrae comunque 800
  righe, quindi leggere il pool intero costa uguale.
- **#20** — a scala piena `--rehearsal-ratio 4` chiede 18.805 × 4 = 75.220 righe da un
  pool che ne ha 10.000: le prende tutte. La selezione stratificata non seleziona nulla,
  e `--rehearsal-strategy` non ha effetto. Cioè: la leva che ha salvato la sonda —
  e su cui è stato speso un commit intero — **nella corsa vera non è collegata a
  niente**. Il ripasso satura sopra ratio ≈ 0,53, e nessun messaggio lo dice.
- **#19** — nella stessa tabella convivevano numeri della sonda (200 righe di
  addestramento) e numeri del run pieno (18.805), senza che la colonna lo dicesse.
  Leggendoli come confrontabili si conclude che una ricetta «non si riproduce», mentre
  semplicemente non era mai stato eseguito lo stesso esperimento.

- **#21** — `normalize_entities()` in valutazione fonde due span adiacenti dello stesso
  tag (deve: nel gold 'Mario'/'Rossi' sono `GIVENNAME`+`SURNAME` separati). `_merge()`
  nell'app non lo faceva. Risultato: `FULLNAME` sul test congelato risultava **2446 →
  2454, un miglioramento**, mentre il prodotto emetteva `[FULLNAME_1] [FULLNAME_2]` —
  che per un LLM a valle sono due persone diverse. Misurato con
  `src/training/fragmentation.py` sulla riserva (1.000 righe, rete core): il
  fine-tuning spezza `FULLNAME` nell'**1,8%** dei casi contro lo **0,3%** del
  checkpoint di partenza, e su tutti i tag **13,7%** contro **11,5%**.
  Il difetto era invisibile perché la misura e l'app avevano due semantiche diverse
  per la stessa operazione, e la misura era quella che rispondeva.

  **Coda del gemello, 2026-08-04: il numero della toppa era a sua volta un gemello.**
  Le prime cifre pubblicate — 9,9% contro 0,3% — venivano dall'apparato rotto di #23 e
  da un conteggio a mano, mai scriptato. Quella del checkpoint di partenza ha retto,
  quella del fine-tuning era sbagliata di cinque volte. Una misura che corregge un
  difetto di misura va scritta come codice con dei test, altrimenti eredita il
  problema che sta risolvendo.

  Nota su cosa NON si fonde: gli span **validati**. Un IP o un CF sono completi per
  costruzione, quindi due accanto sono due entità — fonderli maschererebbe
  `203.0.113.1 203.0.113.2` con un solo segnaposto.

- **#23** — `from_bio()` ricostruiva il testo unendo TUTTI i token con uno spazio, ma
  quelli della validation sono WordPiece: `CAP` diventava `CA ##P`. Il **63,7%** delle
  righe conteneva marcatori e il **45,8%** delle entità del gold ne aveva uno dentro il
  proprio span. Il docstring lo sapeva a metà — «gold e predizione partono dallo stesso
  testo, quindi il confronto resta valido» — vero per l'A/B, falso per tutto il resto.
  L'effetto non era di deprimere i numeri ma di **gonfiarli**: gli identificatori
  lunghi risultavano pre-spezzati esattamente sui confini del gold, quindi `ID_DOC` per
  la baseline passava da 190 su 210 a **40** una volta corretto. Trovato inseguendo
  tutt'altro: il detector `ZIPCODE` nuovo trovava 0 CAP su 87 nel legale.

- **#24** — **due checkpoint indistinguibili dall'app che li carica.** `rizzo-pii-0.3B-base` e
  `rizzo-pii-0.3B-security` hanno `id2label` identico, 44 etichette, e dentro un pacchetto
  PyInstaller `MODEL_DIR` è sempre `.../pii_model`: da un'app in esecuzione non c'era **nessun**
  modo di sapere quale dei due stesse rispondendo. Un utente che riportava un risultato non poteva
  dire su cosa l'aveva ottenuto. Chiuso da `model_info.py`: il timbro si calcola al build, quando
  si sa ancora quale checkpoint si sta copiando, e `GET /model` lo espone. La forma del difetto è
  la solita: **ciò che un artefatto è contro ciò che dichiara di essere**.

- **#25** — **la stessa regola di risoluzione del modello, scritta due volte.** `app.py` e
  `src/training/test_pii.py` sceglievano il checkpoint con codice diverso: la CLI non validava
  l'override e ordinava le versioni con una chiave sua. Le due *politiche* possono divergere
  legittimamente (l'app fissa una versione, la CLI prende l'ultima), la *meccanica* no. Ora è una
  sola, in `server_config.resolve_model_dir()`, e un test guarda il sorgente della CLI perché
  importarla eseguirebbe argparse e caricherebbe 1,2 GB.

  Sottocaso trovato scrivendo la correzione: `GET /model` leggeva `id2label` mentre `known_tags()`
  legge `label2id`. Due campi diversi per la stessa domanda — un gemello nuovo, introdotto proprio
  dal commit che ne chiudeva un altro. Se ne è accorto un test che passava da solo e falliva nella
  suite.

E uno che **non** è un gemello ma appartiene alla stessa famiglia — due cose che
dovrebbero coincidere e non coincidono — perché merita di essere ricordato:
`predict_entities` restituiva `' Stefano Fabbri'` invece di `'Stefano Fabbri'`. Un
carattere di differenza fra lo span del tokenizer e quello del gold, e `FULLNAME`,
`CITY` e `ORG` a **0.000**.

Il metodo che tiene insieme questo registro sta in [METODO.md](METODO.md).

## Perché non basta rileggere il codice

Ognuno di questi difetti è passato sotto i miei occhi mentre guardavo proprio quel
file. Il registro non rende più attenti: rende esplicito **l'elenco delle cose da
confrontare**, che è l'unica parte del problema che si scrive una volta e si riusa.
