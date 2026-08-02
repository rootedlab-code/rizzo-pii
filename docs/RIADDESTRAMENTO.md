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

```bash
head -200  dataset/synthetic/synthetic_security_it_plain_train.jsonl > /tmp/mini_train.jsonl
head -1000 dataset/subsets/train_subset_10k.jsonl                    > /tmp/mini_ripasso.jsonl

python src/training/finetune_security.py \
    --train /tmp/mini_train.jsonl --rehearsal /tmp/mini_ripasso.jsonl \
    --out /tmp/sonda --epochs 1 --batch 4

python src/training/predict_entities.py dataset/validation/validation_real.jsonl \
    --out /tmp/legale_sonda.jsonl --limit 300 --model /tmp/sonda
python src/training/evaluate_entities.py dataset/validation/validation_real.jsonl \
    --pred /tmp/legale_sonda.jsonl --normalize --limit 300 --with-detectors --packs ""
```

**Criterio:** il micro sul legale non deve scendere. Se scende su 180 esempi,
scendera' molto di piu' su 26.851 per due epoche — la sonda e' 150 volte piu'
piccola dell'addestramento vero.

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

Altre leve non ancora provate, se servissero: `--lr 5e-6`, congelare gli strati
bassi, `--max-tag-repeat 1`.

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
