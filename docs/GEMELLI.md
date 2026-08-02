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
| 10 | etichette del training ↔ `label2id` del modello | `bio_of()` scarta ciò che non esiste in `label2id` — **nessun test** | ⚠️ |
| 11 | ambiente locale ↔ ambiente del pod | `preflight.py` confronta le versioni — **da eseguire su entrambi** | ⚠️ |
| 12 | dataset misurato ↔ dataset addestrato | manifesto sha256 in `preflight.py` | ⚠️ |

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

E uno che **non** è un gemello ma appartiene alla stessa famiglia — due cose che
dovrebbero coincidere e non coincidono — perché merita di essere ricordato:
`predict_entities` restituiva `' Stefano Fabbri'` invece di `'Stefano Fabbri'`. Un
carattere di differenza fra lo span del tokenizer e quello del gold, e `FULLNAME`,
`CITY` e `ORG` a **0.000**.

## Perché non basta rileggere il codice

Ognuno di questi difetti è passato sotto i miei occhi mentre guardavo proprio quel
file. Il registro non rende più attenti: rende esplicito **l'elenco delle cose da
confrontare**, che è l'unica parte del problema che si scrive una volta e si riusa.
