# Riaddestramento — cosa fare, in ordine

Procedura per il fine-tuning sui documenti di sicurezza, pensata per essere eseguita
su un pod GPU. Ogni comando e' verificabile: se un numero non viene come descritto,
fermarsi invece di proseguire.

## Cosa si sta facendo, e cosa no

**Si fa** il fine-tuning del checkpoint gia' rilasciato sul dataset `plain`, a
tassonomia **invariata**: `num_labels` non cambia, il modello resta compatibile con
l'app e con `policy.json`. Minuti di GPU, non ore.

**Non si fa** il riaddestramento completo con i tag cyber. Quello cambia
`num_labels`, obbliga a ripartire da `mmBERT-base` con tutte e quattro le fonti del
progetto, e — misurato — dovrebbe battere una rete regex che sui tag cyber sta a
**recall 0.911** con precision 0.989. Prima di pagare quel costo, conviene che il
fine-tuning corto dica se il genere sposta davvero l'ago.

## Le due lacune che il fine-tuning deve chiudere

Misurate sul modello rilasciato, su 31 template mai visti e valori mai visti:

| | |
|---|---|
| `DATE` recall **0.090** | addestrato su date 1955-2005, tronca l'anno: su `24/01/2024` tagga `24/01/20`. ISO **0.000**, esteso **0.002**, ISO+ora **0.054** |
| ~2.700 falsi positivi | 866 `IBAN`, 1.140 `TIME`, 703 `ID_DOC` inventati su hash, identificativi cloud e MAC mai visti |

Il secondo e' il motivo per cui il dataset predefinito **non** etichetta i valori
cyber: servono come `O`.

Nota: la prima lacuna e' gia' **aggirata** in produzione dai detector `DATE`
(recall 0.948). Il fine-tuning serve a risolverla, non ad aggirarla — se un domani
arriva un formato che le regex non coprono, si torna a 0.090.

## 0. Prerequisiti sul pod

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu124   # o la cuda del pod
pip install transformers accelerate
git clone <questo repo> && cd rizzo-pii
```

I dataset non stanno nel repo (`dataset/` e' gitignorata): si rigenerano.

## 1. Dati, con lo split che evita il leakage

```bash
python src/data_pipeline/generate_cyber_pii.py -n 30000 --split train
python src/data_pipeline/generate_cyber_pii.py -n  1200 --split eval
```

**Verifica obbligatoria** — deve stampare `condivisi 0` e `CONDIVISI 0`:

```bash
python - <<'PY'
import json, sys, io, contextlib
sys.path.insert(0, "src/data_pipeline"); sys.path.insert(0, "src/app")
import generate_cyber_pii as cy
with contextlib.redirect_stdout(io.StringIO()):
    tpl = list(cy.TEMPLATES) + cy.load_bank()
tr, ev = cy.split_templates(tpl)
print("template condivisi:", len(set(tr) & set(ev)))
s = lambda p: {cy.skeleton(json.loads(l)) for l in open(p, encoding="utf-8")}
print("scheletri CONDIVISI:",
      len(s("dataset/synthetic/synthetic_security_it_plain_train.jsonl") &
          s("dataset/synthetic/synthetic_security_it_plain_eval.jsonl")))
PY
```

Lo split e' deciso dall'**impronta** di ogni template, non dalla sua posizione:
resta stabile anche se la banca cresce. Se un giorno non desse `0`, c'e' leakage e
qualunque numero successivo e' privo di valore.

## 1-bis. IL PREFLIGHT — gira in secondi, prima di ogni corsa che costa

```bash
python src/training/preflight.py \
    --train dataset/synthetic/security_train_bilanciato.jsonl \
    --eval  dataset/synthetic/synthetic_security_it_plain_eval.jsonl \
    --rehearsal dataset/subsets/train_subset_10k.jsonl \
    --max-len 2048
```

Verifica in un colpo solo le coppie che devono coincidere: impronte dei corpora
contro `dataset/manifesto.json`, **test congelato invariato byte per byte**,
scheletri train/eval disgiunti, `TAG_MAP` allineata col training, determinismo
della normalizzazione, nessun esempio oltre `max_len` — **su tutte le righe di tutti
i file, non su un campione** — e versioni delle librerie.

Tre esiti, non due: `OK`, `FALLITO` e **`N/V`**. Un controllo che non ha potuto
verificare nulla — file assente, libreria mancante — dice *non verificato*, non
*OK*: altrimenti il preflight diventa il difetto che esiste per prevenire.

Sulla macchina di sviluppo l'unico atteso rosso e' `GPU disponibile`. Sul pod deve
essere verde, e va rilanciato **li'**: e' l'unico modo di confrontare i due ambienti
(`docs/GEMELLI.md` #11).

## 2. I DUE numeri di partenza — prima di toccare il modello

Senza questi, dopo non si puo' dire se e' migliorato.

```bash
# a) genere sicurezza
python src/training/predict_entities.py \
    dataset/synthetic/synthetic_security_it_plain_eval.jsonl \
    --out /tmp/pred_sicurezza_PRIMA.jsonl --device 0

python src/training/evaluate_entities.py \
    dataset/synthetic/synthetic_security_it_plain_eval.jsonl \
    --pred /tmp/pred_sicurezza_PRIMA.jsonl --normalize

# b) REGRESSIONE sul caso d'uso originale
curl -sL -o dataset/validation/validation_real.jsonl \
  https://huggingface.co/datasets/rizzoaiacademy/rizzo-pii-it-dataset/resolve/main/validation/validation_real.jsonl

python src/training/predict_entities.py dataset/validation/validation_real.jsonl \
    --out /tmp/pred_legale_PRIMA.jsonl --limit 2000 --device 0

python src/training/evaluate_entities.py dataset/validation/validation_real.jsonl \
    --pred /tmp/pred_legale_PRIMA.jsonl --normalize
```

`--limit 2000` va tenuto **identico** prima e dopo: due campioni diversi non si
confrontano.

### Le baseline gia' misurate (2026-08-02, modello `rizzoaiacademy/rizzo-pii-0.3B`)

Sono i numeri da superare. Se rimisurandoli non vengono uguali, qualcosa e' cambiato
nell'ambiente e va capito prima di addestrare.

**Genere sicurezza** — 1.113 righe, 31 template mai visti, valori mai visti:

| | recall | precision | |
|---|--:|--:|---|
| solo modello | 0.429 | 0.270 | `DATE` 0.090, e ~2.700 entita' inventate su stringhe tecniche |
| modello + regex | **0.854** | **0.703** | `DATE` 0.948 grazie ai detector aggiunti |

**Validation legale** — 2.000 righe, controllo di **regressione**:

| | recall | precision |
|---|--:|--:|
| solo modello | 0.719 | 0.582 |
| **modello + regex core** | **0.783** | **0.712** |

La differenza fra le due righe e' istruttiva: il modello **frammenta** gli
identificatori lunghi — `RCCMRT60T58H703I` esce come `CF`+`CF`+`ID_DOC`+`ID_DOC`+`CF`
— e sono i checksum della rete core a recuperarli (`CF` da 0.018 a 1.000, `PIVA` da
0.145 a 0.961). Misurare il modello da solo su quei tag misura qualcosa che in
produzione non decide niente: **il numero da confrontare e' sempre quello del
sistema**.

Debolezze del sistema sul legale, per riferimento: `DOCID` 0.083,
`CREDITCARDNUMBER` 0.090, `AMOUNT` 0.140, `IBAN` 0.287, `DATE` 0.295,
`CATASTO` 0.371, `ZIPCODE` 0.379, `AGE` 0.445.

Nota utile: sul legale `DATE` sta a **0.295**, e i detector `DATE` che risolvono il
problema stanno nel pacchetto `cyber`, quindi un utente del dominio legale oggi non
li ha. Sono deterministici e validati sul calendario: non c'e' ragione tecnica per
cui debbano restare dietro un'opzione opt-in — solo la scelta, che non e' nostra, di
dove metterli.

## 2-bis. LA SONDA — da superare PRIMA di accendere il pod

Costa cinque minuti su CPU e ha gia' bocciato la ricetta iniziale. Non e' una
formalita': e' il motivo per cui il pod non va acceso adesso.

> **IL POOL DI RIPASSO NON SI TRONCA (misurato il 2026-08-03).** La procedura
> prendeva `head -1000` di `train_subset_10k.jsonl`. In quelle prime 1000 righe ci
> sono **zero** righe con `CATASTO`, **zero** con `DOCID`, **zero** con `TARGA`; il
> pool intero ne ha rispettivamente 682, 1.556 e 424.
>
> Il ripasso stratificato esiste *apposta* per coprire i tag che i dati nuovi non
> contengono, e `CATASTO` e' il primo di quella lista. Troncando il pool, la sonda
> non poteva coprirlo: era **cieca proprio al meccanismo che doveva collaudare**, e
> il crollo di `CATASTO` che riportava era un artefatto del suo campione.
>
> Il troncamento serviva a rendere veloce la sonda, ma non serviva a niente: il
> ripasso ne estrae comunque 800 righe, quindi leggere il pool intero **non cambia
> il costo dell'addestramento**. Il comando qui sotto e' gia' corretto.
>
> Vale per qualunque sonda futura, non solo per questa: se il campione della sonda
> non e' stratificato come il set completo, la sonda sceglie a caso sulle classi
> che non vede — e lo fa in silenzio.

```bash
head -200 dataset/synthetic/security_train_bilanciato.jsonl > /tmp/mini_train.jsonl

python src/training/finetune_security.py \
    --train /tmp/mini_train.jsonl \
    --rehearsal dataset/subsets/train_subset_10k.jsonl \
    --rehearsal-strategy stratified --rehearsal-ratio 4 \
    --out /tmp/sonda --epochs 1 --batch 4 --accum 1

python src/training/predict_entities.py dataset/validation/validation_real.jsonl \
    --out /tmp/legale_sonda.jsonl --limit 300 --model /tmp/sonda
python src/training/evaluate_entities.py dataset/validation/validation_real.jsonl \
    --pred /tmp/legale_sonda.jsonl --normalize --limit 300 --with-detectors --packs ""
```

**Criterio: la tabella PER TAG, non il micro.** Il micro puo' salire mentre singoli
tag crollano, ed e' successo davvero: la ricetta con ripasso 4:1 e `--max-tag-repeat
2` dava micro 0.789 -> 0.793 sul legale, quindi "nessuna regressione", mentre
`CATASTO` scendeva di **12.5 punti** (0.371 -> 0.246), `ZIPCODE` di 9.2 e altri tre
tag di 3-5. Guadagnava tanto su `DATE` — che i nostri dati insegnano — e quel
guadagno, pesato, copriva le perdite.

Il micro sul legale non deve scendere, Se scende su 180 esempi,
scendera' molto di piu' su 26.851 per due epoche — la sonda e' 150 volte piu'
piccola dell'addestramento vero.

### La rimisura del 2026-08-03, e cosa ha invalidato

Rieseguita la sonda dopo che le righe interamente `O` hanno smesso di essere
scartate (2.980 righe, il 15,8% del corpus bilanciato — vedi `GEMELLI.md` #13).
Misurato su **2.000 righe / 4.346 entita'** della validation legale, sistema
completo (modello + rete regex core), con la baseline **riprodotta esatta**
(`0.789` recall, `0.718` precision: le stesse cifre registrate il 2026-08-02, quindi
l'apparato di misura non e' cambiato).

| configurazione della sonda | micro recall | precision | `CATASTO` (345 gold) |
|---|--:|--:|--:|
| baseline (rilasciato) | **0.789** | **0.718** | 0.371 |
| ricetta registrata (righe tutto-`O` scartate, `max_len` 512) | 0.781 | 0.719 | 0.197 |
| ricetta attuale (righe tutto-`O` incluse, `max_len` 2048) | 0.776 | 0.711 | 0.183 |

**McNemar esatto appaiato** sulle 4.346 entita' — il test che il criterio richiede,
non intervalli separati:

| confronto | solo A | solo B | p | esito |
|---|--:|--:|--:|---|
| baseline vs registrata | 136 | 101 | 0.027 | diversi |
| baseline vs attuale | 116 | 61 | 0.000043 | diversi |
| **registrata vs attuale** | 78 | 58 | **0.103** | **indistinguibili** |

Due conclusioni, di peso molto diverso.

**Le righe tutto-`O` e `max_len` 2048 non spiegano niente.** p = 0.103 fra le due
configurazioni, su un campione che invece separa benissimo entrambe dalla baseline
(p = 0.00004). Chi cercasse in quella modifica la causa di una regressione starebbe
inseguendo rumore.

**Ma nessuno di questi numeri dice qualcosa sulla ricetta**, perche' sono stati
prodotti con il pool di ripasso troncato (riquadro sopra): senza una riga di
`CATASTO` da cui pescare, il tag che decide era condannato in partenza in *tutte* le
configurazioni. Restano validi solo come misura di **due sonde fra loro**, ed e'
esattamente la domanda a cui rispondono.

Una sonda a 300 righe non basta nemmeno per quello: sulle stesse tre configurazioni,
a `--limit 300` (634 entita') il test appaiato le dava **tutte e tre
indistinguibili** (p = 0.265, 0.053, 0.678). La differenza minima rilevabile va
calcolata prima di lanciare, non scoperta dopo: a 634 entita' questa sonda non puo'
decidere ne' assolvere niente.

### La stessa sonda, con il pool di ripasso non troncato

Unico asse cambiato: `--rehearsal dataset/subsets/train_subset_10k.jsonl` invece di
`head -1000`. Stessi dati nuovi, stesso ripasso 4:1 stratificato, stesso seed,
stesso numero di esempi (1.000) e quindi stesso numero di passi.

| | micro recall | precision | `CATASTO` | McNemar vs baseline |
|---|--:|--:|--:|---|
| baseline (rilasciato) | 0.789 | 0.718 | 0.371 | — |
| sonda, pool **troncato** | 0.776 | 0.711 | 0.183 (−0.188) | 116/61, **p = 0.000043** |
| sonda, pool **intero** | **0.785** | **0.716** | **0.325 (−0.046)** | 81/65, **p = 0.214** |

`CATASTO` recupera **14 punti** e il sistema passa da *significativamente peggiore
della baseline* a *indistinguibile da essa*. Il verdetto della sonda non descriveva
la ricetta: descriveva il proprio campione.

Vale la pena dirlo per esteso, perche' e' il difetto piu' costoso di tutto il
lavoro. `stratified_rehearsal()` costruisce l'elenco dei tag da proteggere
**leggendo il pool**. Un tag assente dal pool non risulta scoperto: risulta
inesistente, e nessuno lo protegge. Con `head -1000` erano invisibili `CATASTO`,
`DOCID` e `TARGA` — i tag da proteggere passavano da 11 a 6 — e il crollo di
`CATASTO` che la sonda riportava era inevitabile in *ogni* configurazione, quindi
non poteva distinguerne nessuna.

### Cosa ha gia' detto la sonda (2026-08-02)

| configurazione | micro recall | precision |
|---|--:|--:|
| modello rilasciato | **0.817** | 0.752 |
| dopo fine-tuning, senza ripasso | 0.759 | 0.700 |
| dopo fine-tuning, ripasso 1:1 | 0.767 | 0.704 |

`TARGA` passa da 0.667 a 0.000 senza ripasso. E' dimenticanza catastrofica, e il
ripasso 1:1 la riduce appena.

### RICETTA CHE PASSA LA SONDA (2026-08-02)

Due leve insieme, e servono entrambe:

```bash
python src/data_pipeline/generate_cyber_pii.py -n 30000 --split train \
    --max-tag-repeat 2 --out dataset/synthetic/security_train_bilanciato.jsonl

python src/training/finetune_security.py \
    --train dataset/synthetic/security_train_bilanciato.jsonl \
    --rehearsal dataset/subsets/train_subset_10k.jsonl --rehearsal-ratio 4 \
    --out models/rizzo-pii-0.3B-security
```

| configurazione | legale recall | precision | F1 |
|---|--:|--:|--:|
| baseline (rilasciato) | 0.823 | 0.758 | 0.789 |
| senza ripasso | 0.763 | 0.705 | 0.733 |
| ripasso 1:1 | 0.771 | 0.709 | 0.739 |
| ripasso 4:1 | 0.787 | 0.724 | 0.754 |
| **ripasso 4:1 + `--max-tag-repeat 2`** | **0.822** | **0.763** | **0.791** |

Confermata su 2.000 righe (4.346 entita'): micro 0.789 -> **0.793**, precision 0.718
-> **0.730**. Ma vedere sotto: **il micro non basta**.

### Il micro mentiva — dettaglio per tag su 2.000 righe

| tag | prima | dopo | | gold |
|---|--:|--:|--:|--:|
| `DATE` | 0.295 | **0.591** | +0.296 | 264 |
| `AMOUNT` | 0.140 | 0.279 | +0.139 | 43 |
| `AGE` | 0.445 | 0.571 | +0.126 | 119 |
| **`CATASTO`** | 0.371 | **0.246** | **-0.125** | **345** |
| **`ZIPCODE`** | 0.379 | 0.287 | -0.092 | 87 |
| `BUILDINGNUM` | 0.679 | 0.628 | -0.051 | 156 |
| `ID_DOC` | 0.905 | 0.862 | -0.043 | 210 |
| `TIME` | 0.959 | 0.924 | -0.035 | 171 |

Il modello **baratta**: guadagna su cio' che i nostri dati contengono e perde su
cinque tag legali, fra cui `CATASTO`, che nel nostro dataset non esiste affatto ed e'
il secondo tag per frequenza nella validation.

Non e' un problema di quantita' di ripasso: nelle 800 righe usate ci sono 186 entita'
`CATASTO` e 386 `ZIPCODE`, e in termini di entita' il ripasso domina gia' 9 a 1
(6.347 contro ~700). La deriva va ridotta alla fonte — learning rate piu' basso,
oppure congelare gli strati bassi — non compensata con altro ripasso.

Il ripasso da solo non basta (si ferma a 0.787): serve anche riequilibrare `DATE`,
che passa dal 64.1% al 38.8% delle entita'. Il perche' e' nella densita': non e' uno
squilibrio diffuso ma una coda di righe di tipo timeline con 7-9 date ciascuna.

**Il prezzo, da sapere:** quella coda *e'* il genere timeline, cioe' una parte di
cio' che il dataset dovrebbe insegnare. Si scambia rappresentativita' con equilibrio.

E il training funziona anche in avanti, misurato su 400 righe di sicurezza con
**200 soli esempi** di addestramento (il vero run ne avra' 18.805):

| | sicurezza recall | precision |
|---|--:|--:|
| rilasciato | 0.438 | 0.213 |
| dopo | **0.533** | **0.360** |

`DATE` da 0.075 a 0.245 con 200 esempi. Non e' ancora il livello dei detector
(0.948), ma la direzione e' quella giusta e la scala e' 90 volte piu' piccola.

Altre leve non ancora provate, se servissero: `--lr 5e-6`, `--max-tag-repeat 1`, e
**`--freeze-encoder`**, che congela l'encoder e addestra la sola testa
(`head.dense`, `head.norm`, `classifier`): **624.428 parametri su 307.564.076, lo
0,203%**. E' la leva piu' forte contro la dimenticanza — il modello non puo'
scordare cio' che non puo' modificare — e per la stessa ragione la piu' limitata
nell'imparare. Va misurata sapendolo, non assunta.

Quando confronti due varianti tieni **costante il batch efficace** (`--batch` x
`--accum`, oggi 8 x 2 = 16): cambiarlo cambia il numero di passi di ottimizzazione,
cioe' stai confrontando due esperimenti invece di due ricette. `finetune.json`
registra entrambi i valori insieme a ogni altra leva.

**Cautela sul campione:** la sonda usa 300 righe (634 entita'). Le differenze di
cinque punti sono un segnale, non una misura di precisione. Prima di dichiarare
risolto qualcosa, rimisurare su `--limit 2000`.

## 3. Fine-tuning

```bash
python src/training/finetune_security.py \
    --train dataset/synthetic/synthetic_security_it_plain_train.jsonl \
    --out   models/rizzo-pii-0.3B-security
```

Deve stampare `num_labels INVARIATO`. Se cambia, si sta facendo l'altra cosa.

## 4. I due numeri di arrivo, e la decisione

Stessi comandi del punto 2, con `--model models/rizzo-pii-0.3B-security`.

| esito | decisione |
|---|---|
| sicurezza **sale**, legale **stabile** | il fine-tuning ha funzionato: si puo' sostituire |
| sicurezza sale, legale **scende** | **non e' un miglioramento, e' uno scambio.** Meno epoche, learning rate piu' basso, o mescolare dati legali nel training |
| sicurezza non sale | il genere non era il problema: guardare `--labels DATE` e i falsi positivi per tag prima di insistere |

Il secondo caso e' quello che si trascura sempre, perche' richiede di misurare
qualcosa che non si sta cercando di migliorare.

## 5. Se e solo se serve: i tag cyber

Solo dopo che il punto 4 ha dato un esito, e sapendo che il campione da battere e'
**recall 0.911**:

```bash
python src/data_pipeline/generate_cyber_pii.py -n 30000 --split train --label-cyber
python src/training/evaluate_entities.py \
    dataset/synthetic/synthetic_security_it_cyberlabeled_eval.jsonl \
    --labels IP,DOMAIN,URL,HASH,MAC,ASN,WALLET,CLOUDID,PATH,USER
```

Il secondo comando ristampa il campione da battere. `num_labels` cambia, quindi
serve `train_pii.py` con tutte e quattro le fonti, non questo script.

## Limiti da tenere presenti

- **La distribuzione degli IP e' irrealistica per costruzione**: tre `/24` documentali
  piu' RFC 1918. Con `--label-cyber` il modello imparerebbe che «IP» significa «comincia
  con quei prefissi». Lo split sui valori misura quanto, ma non lo elimina.
- **Manca l'iniezione in frasi reali** (`augment_real_pii.py`), l'arma migliore del
  progetto contro l'overfit strutturale: per il genere sicurezza non esiste un corpus
  pubblico utilizzabile, e quello d'ingaggio e' escluso.
- I dati sono al 100% da template. Il cap a 20 righe per scheletro riduce la
  ripetitivita', non la elimina.
