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

| tag | entità recuperate |
|---|--:|
| `DATE` | +61 |
| `ID_DOC` | +28 |
| `CATASTO` | +18 |
| `BUILDINGNUM` | +13 |
| `CITY` | +12 |

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

## A cosa NON serve

- **Non è una garanzia di anonimizzazione.** Nessun modello di token classification lo
  è. Quattro tag restano sotto 0.5 di recall anche dopo il fine-tuning:
  `CREDITCARDNUMBER`, `IBAN`, `AMOUNT`, `ZIPCODE`.
- **Non copre i tag cyber** (IP, hash, wallet, identificativi cloud, ASN, MAC). Restano
  ai detector deterministici, che su di essi stanno a recall 0.911 con precision 0.989:
  un modello dovrebbe battere quel campione per giustificare il costo. Nel dataset di
  addestramento quei valori compaiono **senza etichetta**, di proposito — servono a
  insegnare che una stringa tecnica è `O`.
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
