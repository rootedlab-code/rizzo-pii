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

E uno che **non** è un gemello ma appartiene alla stessa famiglia — due cose che
dovrebbero coincidere e non coincidono — perché merita di essere ricordato:
`predict_entities` restituiva `' Stefano Fabbri'` invece di `'Stefano Fabbri'`. Un
carattere di differenza fra lo span del tokenizer e quello del gold, e `FULLNAME`,
`CITY` e `ORG` a **0.000**.

## Perché non basta rileggere il codice

Ognuno di questi difetti è passato sotto i miei occhi mentre guardavo proprio quel
file. Il registro non rende più attenti: rende esplicito **l'elenco delle cose da
confrontare**, che è l'unica parte del problema che si scrive una volta e si riusa.
