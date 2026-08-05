---
license: mit
language:
  - it
library_name: transformers
pipeline_tag: token-classification
base_model: rizzoaiacademy/rizzo-pii-0.3B
tags:
  - pii
  - anonymization
  - italian
  - token-classification
  - security
---

# rizzo-pii-0.3B-security

Fine-tuning di [`rizzoaiacademy/rizzo-pii-0.3B`](https://huggingface.co/rizzoaiacademy/rizzo-pii-0.3B)
sul **genere documentale "sicurezza"** — verbali d'incidente, timeline forensi, ticket,
estratti di log — a **tassonomia invariata**: `num_labels` non cambia, quindi il
modello resta compatibile con l'applicazione, con i 22 tag e con i profili di policy
esistenti.

Serve ad anonimizzare documenti **in locale** prima di mandarli a un LLM esterno.

> ## ⚠️ Da solo questo modello NON anonimizza un report di sicurezza
>
> Il modello copre i tag "morbidi" — nomi, date, città, organizzazioni, indirizzi — cioè
> quelli che nessuna espressione regolare può decidere. **Non copre gli indicatori
> tecnici**: IP, domini, URL, hash, MAC, ASN, wallet, identificativi cloud. Quelli li
> risolve una rete di **detector deterministici** che sta nel codice, non nei pesi.
>
> Se lo usi da solo, l'effetto non è "l'IP resta in chiaro": è **peggio**. Stessa frase,
> stesso checkpoint, cambia solo il pacchetto di detector:
>
> ```
> ingresso            L'host colpito ha isolato 203.0.113.42.
> senza i detector →  L'host colpito ha isolato 203[ID_DOC_1]42.   ← MUTILATO
> con i detector   →  L'host colpito ha isolato [IP_1].
> ```
>
> Riproducibile con il modello scaricato in `models/rizzo-pii-0.3B-security/`, una volta
> senza e una volta con il pacchetto:
>
> ```bash
> export PII_MODEL_DIR=$PWD/models/rizzo-pii-0.3B-security
> python src/app/app.py --port 5099                     # senza: solo la rete core
> python src/app/app.py --port 5099 --detectors cyber   # con
> curl -s localhost:5099/analyze -H 'Content-Type: application/json' \
>      --data '{"text": "L'\''host colpito ha isolato 203.0.113.42."}'
> ```
>
> Il modello inventa un'entità su un pezzo dell'indirizzo e lascia leggibile il resto: il
> documento **sembra** protetto proprio dove non lo è. Il punto di taglio si sposta con la
> frase — altrove escono due segnaposto per due punti, e un secondo indirizzo nella stessa
> riga resta intero — ed è la parte peggiore: nello stesso documento uno esce rotto e
> l'altro no, e a occhio non si distingue quale.
>
> **Il codice che serve — detector cyber, policy per ruolo, scope d'ingaggio — vive
> qui:** [`rootedlab-code/rizzo-pii`, branch `dev`](https://github.com/rootedlab-code/rizzo-pii/tree/dev).
> Non è nel repository di partenza. Comando minimo:
>
> ```bash
> python src/app/app.py --detectors cyber --profile security-report \
>                       --scope-file ~/ingaggi/acme/scope.json
> ```
>
> Le tre parti e il perché sono spiegate in [Uso su documenti di sicurezza](#uso-su-documenti-di-sicurezza).

## Cosa cambia rispetto al modello di partenza

Il checkpoint originale è addestrato su prosa legale italiana. Sui documenti di
sicurezza peggiorava proprio dove il modello è indispensabile — cioè sui tag che la
rete di regex **non** copre — e aveva due lacune misurate:

1. **`DATE` a recall 0.090.** Addestrato su date fra il 1955 e il 2005 (l'intervallo
   delle date di nascita), troncava l'anno: su `24/01/2024` etichettava `24/01/20`. Il
   formato ISO non lo riconosceva affatto.
2. **~2.700 entità inventate** su stringhe tecniche mai viste: 866 `IBAN`, 1.140
   `TIME`, 703 `ID_DOC` prodotti da hash, identificativi cloud e indirizzi MAC.

Questo modello chiude entrambe.

## Risultati

Misurati su un **campione cieco** di 1.000 righe (2.279 entità), mai viste durante lo
sviluppo, contro un criterio scritto e depositato *prima* di guardare i numeri.
Sistema completo — modello + rete regex/checksum core — come gira in produzione.

| | recall | precision | F1 | PII lasciate in chiaro |
|---|--:|--:|--:|--:|
| `rizzo-pii-0.3B` | 0.737 | 0.670 | 0.702 | 600 |
| **questo modello** | **0.808** | **0.742** | **0.773** | **438** |

**162 PII in meno** lasciate in chiaro su 2.279, e 185 falsi positivi in meno.

Il confronto è **appaiato** (McNemar esatto sulle stesse entità, non due intervalli
affiancati): **182 entità recuperate contro 20 perse**, p < 1e-6.

Per tag, fra i 9 con almeno 100 entità nel gold: cinque migliorano in modo
statisticamente distinguibile, quattro restano invariati, **nessuno peggiora**.

### Tabella completa, tag per tag

Tutti e 22 i tag della tassonomia, misurati sullo stesso campione cieco, con lo stesso
apparato, nello stesso momento. **Sistema completo** — modello + rete regex/checksum —
perché è così che gira in produzione: misurare il solo modello direbbe quanto è bravo il
modello, che non è il prodotto.

La colonna che conta per chi scrive report è **«in chiaro»**: quante PII presenti nel
documento **non** sono state mascherate. È il rischio, non il punteggio.

| tag | entità | recall base | recall fork | Δ | in chiaro base → fork | affidabilità (fork) |
|---|--:|--:|--:|--:|--:|---|
| `FULLNAME` | 617 | 0.972 | **0.976** | **+0.004** | 17 → **15** | affidabile |
| `CATASTO` | 165 | 0.309 | **0.400** | **+0.091** | 114 → **99** | **debole — rileggi a mano** |
| `CITY` | 145 | 0.869 | **0.945** | **+0.076** | 19 → **8** | buono |
| `ID_DOC` | 135 | 0.207 | **0.407** | **+0.200** | 107 → **80** | **debole — rileggi a mano** |
| `EMAIL` | 123 | 1.000 | **1.000** | = | 0 → **0** | affidabile |
| `DATE` | 122 | 0.385 | **0.885** | **+0.500** | 75 → **14** | buono |
| `TELEPHONENUM` | 122 | 0.943 | **0.951** | **+0.008** | 7 → **6** | affidabile |
| `STREET` | 106 | 0.962 | **0.962** | = | 4 → **4** | affidabile |
| `BUILDINGNUM` | 102 | 0.676 | **0.794** | **+0.118** | 33 → **21** | buono |
| `TIME` | 84 | 0.976 | **0.988** | **+0.012** | 2 → **1** | affidabile |
| `PIVA` | 74 | 0.743 | **0.770** | **+0.027** | 19 → **17** | buono |
| `CF` | 68 | 1.000 | **1.000** | = | 0 → **0** | affidabile |
| `GENDER` | 64 | 0.953 | **0.953** | = | 3 → **3** | affidabile |
| `PROVINCE` | 63 | 1.000 | **1.000** | = | 0 → **0** | affidabile |
| `DOCID` | 55 | 0.109 | **0.327** | **+0.218** | 49 → **37** | **debole — rileggi a mano** |
| `ZIPCODE` | 53 | 0.094 | **0.226** | **+0.132** | 48 → **41** | **debole — rileggi a mano** |
| `AGE` | 45 | 0.600 | **0.600** | = | 18 → **18** | parziale |
| `IBAN` | 42 | 0.357 | **0.357** | = | 27 → **27** | **debole — rileggi a mano** |
| `CREDITCARDNUMBER` | 38 | 0.132 | **0.132** | = | 33 → **33** | **debole — rileggi a mano** |
| `AMOUNT` | 28 | 0.107 | **0.500** | **+0.393** | 25 → **14** | **debole — rileggi a mano** |
| `ORG` | 20 | 1.000 | **1.000** | = | 0 → **0** | affidabile |
| `TARGA` | 8 | 1.000 | **1.000** | = | 0 → **0** | affidabile |
| **TOTALE (micro)** | **2.279** | **0.737** | **0.808** | **+0.071** | **600 → 438** | — |

**Zero tag peggiorano in recall.** Il totale delle PII lasciate in chiaro passa da 600 a
**438 su 2.279**: 162 in meno, sullo stesso testo.

**Ma sette tag restano a 0.5 o sotto**, e su quelli il sistema **non basta**:
`CREDITCARDNUMBER` (0.132), `ZIPCODE` (0.226), `DOCID` (0.327), `IBAN` (0.357),
`CATASTO` (0.400), `ID_DOC` (0.407), `AMOUNT` (0.500). Cinque dei sette migliorano
rispetto al modello di partenza, ma migliorare non è bastare: se il tuo documento
contiene carte di credito, coordinate catastali o numeri di repertorio, quelle righe
vanno rilette a mano.

Nota su `IBAN` e `CF`: nella tabella `CF` è a 1.000 e `IBAN` a 0.357 perché il primo ha
un checksum verificabile e il secondo, nel gold, compare spesso in forme che la rete non
convalida. Dove il checksum passa, la rete è esatta e vince sul modello.

**Come si rifà il conto, e cosa lo limita.** Il campione cieco **non è distribuito**:
deriva da Ai4Privacy (CC-BY-4.0) e DeepMount, licenze di terzi mai verificate per la
ridistribuzione. Quindi questa tabella **non è riproducibile da fuori** — è un limite
reale, non un dettaglio. Quello che è versionato è la sua **impronta**
(`dataset/validation/test_riserva.sha256`), che permette almeno di provare di avere lo
stesso file di 1.000 righe. Chi ce l'ha rigenera tutto con tre comandi:

```bash
python src/training/predict_entities.py dataset/validation/test_riserva_legale.jsonl \
    --out pred.jsonl --model <checkpoint>
python src/training/evaluate_entities.py dataset/validation/test_riserva_legale.jsonl \
    --pred pred.jsonl --with-detectors --packs "" --normalize
python src/training/mcnemar.py dataset/validation/test_riserva_legale.jsonl \
    --a pred_base.jsonl --b pred_fork.jsonl --per-tag 100
```

> **Una versione precedente di questa scheda riportava 0.806 → 0.858.** Quei numeri
> venivano da un apparato di valutazione che ricostruiva il testo unendo i token
> WordPiece con uno spazio: `CAP` diventava `CA ##P`, e il 46% delle entità del gold
> aveva un marcatore dentro il proprio span. L'effetto non era di deprimere i
> risultati ma di **gonfiarli**, perché gli identificatori lunghi risultavano
> pre-spezzati esattamente sui confini attesi. Corretto l'apparato, la misura è stata
> rifatta su un campione cieco mai usato. Il confronto A/B era comunque valido —
> entrambi i modelli sullo stesso testo — quindi la decisione di rilascio non cambia,
> cambiano i valori assoluti.

Sul genere sicurezza il recall passa da 0.893 a **0.939**, e `DATE` da 0.090 a
**0.959**. Quel corpus non ha artefatti di tokenizzazione, quindi quei numeri non
sono stati toccati dalla correzione.

> **I numeri valgono per il sistema con la fusione degli span adiacenti** (`_fuse_adjacent`
> in `app.py`, dal 2026-08-03). Senza la fusione i frammenti arrivano all'utente come
> segnaposto distinti — `[FULLNAME_1] [FULLNAME_2]` sono due persone diverse per l'LLM
> a valle — e su quell'asse **questo modello e' peggiore del checkpoint di partenza**:
>
> | frammentazione (senza fusione) | `rizzo-pii-0.3B` | questo modello |
> |---|--:|--:|
> | `FULLNAME` | **0,3%** | **1,8%** |
> | tutti i tag (micro) | **11,5%** | **13,7%** |
>
> Il fine-tuning recupera entita' che il checkpoint di partenza non trovava affatto, ma
> quelle che trova le emette spezzate un po' piu' spesso. La fusione lo ripara a livello
> di prodotto; senza, il documento anonimizzato e' meno leggibile a valle.
>
> Riproducibile — 1.000 righe, rete regex core, gli stessi due file di predizioni:
>
> ```bash
> python src/training/predict_entities.py dataset/validation/test_riserva_legale.jsonl \
>     --out /tmp/pred.jsonl --model <checkpoint>
> python src/training/fragmentation.py dataset/validation/test_riserva_legale.jsonl \
>     --pred /tmp/pred.jsonl
> ```
>
> **Una misura precedente riportava 9,9% contro 0,3%.** Veniva dallo stesso apparato
> difettoso di cui sopra e non era riproducibile da nessun comando: era stata calcolata
> una volta sola, a mano. Il valore del checkpoint di partenza si e' confermato, quello
> di questo modello no.
>
> Perche' la misura non lo mostrava: l'attrezzatura di valutazione fonde gli span
> adiacenti mentre l'app non lo faceva, quindi le due davano risposte diverse alla
> stessa domanda — e rispondeva quella della misura.
>
> I numeri qui sopra **non sono confrontabili** con il micro-F1 dichiarato dal modello
> di partenza: quello è misurato sulla sua validation con il suo apparato, questo su un
> campione cieco diverso e a livello di sistema. L'unico confronto valido è quello
> riportato in tabella, dove entrambi i modelli sono stati misurati sullo stesso
> hardware, sulle stesse righe, nello stesso momento.

## Uso

```python
from transformers import pipeline

nlp = pipeline("token-classification",
               model="dr3x1/rizzo-pii-0.3B-security",
               aggregation_strategy="simple")
nlp("Il 24/01/2024 l'analista Mario Rossi ha isolato l'host colpito.")
```

In produzione va affiancato **sempre** alla rete regex+checksum: su codice fiscale,
partita IVA, IBAN e carte di credito quella è esatta, mentre il modello frammenta gli
identificatori lunghi (`RCCMRT60T58H703I` esce come `CF`+`CF`+`ID_DOC`+…). Misurato:
`CF` passa da 0.018 col solo modello a 1.000 col checksum.

## Uso su documenti di sicurezza

Il sistema ha **tre assi**, e il modello è uno solo dei tre. Saltarne uno non produce un
errore: produce un documento meno protetto di quanto sembri.

| asse | domanda | chi risponde |
|---|---|---|
| **detection** | che tipo di dato è? | il modello (tag morbidi) **+** i detector deterministici (tag tecnici) |
| **scope** | di chi è questo valore? | un file d'ingaggio dichiarato dall'analista |
| **policy** | e quindi cosa ne faccio? | profilo + regole per *(tag, ruolo)* |

**Perché lo scope non è un dettaglio.** In un report l'indirizzo del C2 dell'avversario è
l'oggetto del documento: mascherarlo lo rende inutile e non protegge nessuno. L'indirizzo
del cliente va mascherato. Sono **due IP, identici nella forma, con trattamento opposto** —
`--keep-tags IP` non può esprimerlo, perché `IP` è un tag solo.

```bash
python src/app/app.py --detectors cyber --profile security-report \
                      --scope-file ~/ingaggi/acme/scope.json
```

```json
{
  "own":       {"IP": ["10.0.0.0/8", "203.0.113.5"], "DOMAIN": ["client.example"]},
  "adversary": {"IP": ["198.51.100.7"], "DOMAIN": ["evil.example"]}
}
```

Risultato, misurato su questo checkpoint:

```
Il [DATE_1] [FULLNAME_1] ha rilevato il C2 198.51.100.7 (evil.example)
verso il nostro host [IP_1].
```

Il file d'ingaggio elenca gli indirizzi del cliente e gli indicatori dell'avversario:
è **il file più sensibile del sistema**. Non ha un percorso predefinito, appartiene
all'ingaggio e non all'installazione, e va tenuto **fuori dal repository**, uno per
ingaggio. `GET /scope` riporta quante voci ci sono per ruolo, mai quali, e non ha un
`POST`.

**Senza file d'ingaggio il profilo `security-report` non fa nulla**, ed è un caso da
conoscere: senza ruoli nessuna regola per ruolo può applicarsi, quindi il profilo
equivale a `full` (maschera tutto). L'interfaccia lo dichiara; da riga di comando no.

Codice, documentazione completa e formato dello scope:
[`rootedlab-code/rizzo-pii`, branch `dev`](https://github.com/rootedlab-code/rizzo-pii/tree/dev).

### Non c'è un installer, e non è una mancanza

**Non viene distribuito nessun eseguibile pronto**, né adesso né in programma. Chi vuole
l'applicazione desktop la **compila dal sorgente**: `docs/BUILD.md` sul branch `dev`.

Il motivo è di sicurezza, non di comodità. Un installer da ~2 GB **non firmato** con un
certificato di code signing chiederebbe a un operatore di eseguire un binario di
provenienza non verificabile — per lavorarci sopra documenti che contengono gli indirizzi
del suo cliente e gli indicatori di un avversario. È esattamente l'abitudine che chi fa
questo mestiere passa la giornata a scoraggiare negli altri, e un progetto open source
appena nato non ha né la reputazione né il certificato per chiedere quella fiducia.

Compilare dal sorgente è più lento e **verificabile**: si legge cosa si sta impacchettando.

Cosa serve, in breve: Python con `pyinstaller`, il modello scaricato in
`models/rizzo-pii-0.3B-security/`, e — per la finestra nativa — Rust e Node. Il modello
che finisce nel pacchetto lo decide `PII_BUILD_MODEL`, e il build si ferma subito se
quella directory non è un checkpoint.

Il sidecar (backend Python impacchettato) è stato costruito e provato: parte, risponde, e
dichiara correttamente quale checkpoint contiene. Il bundle completo delle tre
piattaforme **non** è stato verificato qui.

### Quattro difetti trovati usandolo su un documento vero, e risolti

Il modello aveva superato un test cieco da 1.000 righe con tutte le regole. Poi è stato
usato su un **verbale d'assessment reale**, e in una sola esecuzione sono emersi quattro
difetti che nessun holdout aveva mostrato. Sono la ragione per cui questa scheda insiste
sulla rilettura: **un test superato non è un collaudo sul campo.**

| difetto | causa | stato |
|---|---|---|
| 9 orari su 9 lasciati in chiaro | la validation ha orari nei formati che il modello gestisce; i verbali usano orari **tondi** (`08:00`, `14:00`) | ✅ detector `TIME` |
| il dominio del committente in chiaro **7 volte** | il suo TLD non era fra i 119 della lista, e il detector falliva **in silenzio** | ✅ ciò che l'analista dichiara nello scope viene rilevato comunque |
| gli URL con lo **stesso** dominio erano invece mascherati | due percorsi diversi per lo stesso valore: il documento sembrava protetto proprio dove non lo era | ✅ coerenti |
| il 46% degli errori residui era un CAP | nessun detector `ZIPCODE` | ✅ detector `ZIPCODE` |

Riverificati sul checkpoint pubblicato con un documento costruito apposta: orari tondi,
un dominio con TLD fuori lista dichiarato `own`, la sua URL e un CAP. Tutti e quattro
mascherati.

**E una lezione che è diventata una funzione:** una lista chiusa deve dire quando *non
sa*. Se il testo contiene token a forma di dominio con estensioni fuori lista,
l'interfaccia lo segnala esplicitamente — perché in quel caso il documento può sembrare
lavorato e non esserlo.

## A cosa NON serve

- **Non è una garanzia di anonimizzazione.** Nessun modello di token classification lo
  è. **Sette** tag restano a 0.5 di recall o sotto anche dopo il fine-tuning —
  `CREDITCARDNUMBER`, `ZIPCODE`, `DOCID`, `IBAN`, `CATASTO`, `ID_DOC`, `AMOUNT` — e su
  quelli serve una rilettura umana. *(Una stesura precedente di questa scheda ne
  dichiarava quattro: era un elenco scritto a mano, non ricavato dalla tabella. Quella
  qui sopra viene dalla misura.)*
- **Non copre i tag cyber** (IP, hash, wallet, identificativi cloud, ASN, MAC). Restano
  ai detector deterministici di
  [`rootedlab-code/rizzo-pii`](https://github.com/rootedlab-code/rizzo-pii/tree/dev)
  (`src/app/detectors_cyber.py`), che su di essi stanno a recall 0.911 con precision
  0.989: un modello dovrebbe battere quel campione per giustificare il costo. Nel
  dataset di addestramento quei valori compaiono **senza etichetta**, di proposito —
  servono a insegnare che una stringa tecnica è `O`.
- **Non copre il tradecraft.** Nomi di strumenti, VPN, sandbox, procedure non sono PII e
  nessun tag li prevede: un report anonimizzato racconta comunque *come* si lavora.
- **Non sostituisce una rilettura umana.** Riduce di molto cosa resta da guardare; non
  azzera. Il difetto che lo dimostra è stato trovato su un documento vero e non
  dall'holdout — il dominio del committente in chiaro sette volte perché il suo TLD non
  era fra i 119 della lista, mentre gli URL con lo stesso dominio erano mascherati — ed è
  [risolto](#quattro-difetti-trovati-usandolo-su-un-documento-vero-e-risolti): ciò che
  l'analista dichiara nello scope viene rilevato comunque, e i token con estensione fuori
  lista vengono segnalati invece di fallire in silenzio. Resta vera la classe del
  problema: una lista chiusa può essere incompleta altrove, e quando lo è il documento
  sembra protetto proprio dove non lo è.
- **Non è validato fuori dall'italiano.** Il modello di partenza è multilingue, questo
  fine-tuning non ha rimisurato le altre sette lingue.

## Come è stato addestrato

- Corpus di sicurezza sintetico: 18.805 righe da 196 template, con cap di ripetizione
  per scheletro e riequilibrio dei tag sovrarappresentati.
- **Ripasso** del dominio originale: 10.000 righe. Senza, il modello dimentica —
  misurato: 180 esempi di solo genere sicurezza bastano a portare `TARGA` a zero.
- 3 epoche, batch efficace 16, learning rate 2e-5, lunghezza massima 2.048 token
  (misurata: la riga più lunga dei corpora è 1.861).

Il numero di epoche non è una scelta di comodo: `ID_DOC` e `ZIPCODE` si muovono in
direzioni opposte su quell'asse — il primo è dimenticanza e si recupera con più
passaggi sul ripasso, il secondo è interferenza e peggiora con più passaggi sul genere
nuovo. Tre epoche è il punto in cui nessun tag decisivo arretra.

**I dati sintetici non contengono PII reali.** L'LLM scrive solo la prosa con
segnaposto, il codice inietta i valori: le etichette sono esatte per costruzione, i
checksum sono validi, e nessun dato personale vero può essere rigurgitato. Indirizzi,
domini, ASN e MAC vengono **per costruzione** dagli intervalli riservati alla
documentazione (RFC 5737, 1918, 3849, 2606, 5398, 7042), verificato su ogni riga
prodotta.

Limite dichiarato: i dati sono al 100% da template. Manca l'iniezione in frasi reali,
che è la difesa migliore contro l'overfit strutturale — per il genere sicurezza non
esiste un corpus pubblico utilizzabile.

## Licenza e provenienza

**MIT**, come il progetto da cui deriva.

Catena completa: [`jhu-clsp/mmBERT-base`](https://huggingface.co/jhu-clsp/mmBERT-base)
→ [`rizzoaiacademy/rizzo-pii-0.3B`](https://huggingface.co/rizzoaiacademy/rizzo-pii-0.3B)
→ questo modello.

Da [`Rizzo-AI-Academy/rizzo-pii`](https://github.com/Rizzo-AI-Academy/rizzo-pii) di
Simone Rizzo vengono il checkpoint di partenza, la tassonomia a 22 tag, la pipeline di
generazione sintetica e la rete regex+checksum. Copyright del progetto originale
© 2026 Simone Rizzo — Rizzo AI Academy.

Fine-tuning sul genere sicurezza, dataset sintetico di dominio e valutazione:
`rootedlab-code`.

**Dove sta cosa** — i due repository non contengono le stesse cose, ed è il motivo per
cui questa scheda linka entrambi:

| | repository |
|---|---|
| checkpoint di partenza, tassonomia, pipeline sintetica, rete regex core | [`Rizzo-AI-Academy/rizzo-pii`](https://github.com/Rizzo-AI-Academy/rizzo-pii) |
| **detector cyber, policy per ruolo, scope d'ingaggio** — ciò che serve per usare questo modello su report di sicurezza | [`rootedlab-code/rizzo-pii`, branch `dev`](https://github.com/rootedlab-code/rizzo-pii/tree/dev) |
| corpus sintetico del genere sicurezza | [`dr3x1/rizzo-pii-security-it`](https://huggingface.co/datasets/dr3x1/rizzo-pii-security-it) |
