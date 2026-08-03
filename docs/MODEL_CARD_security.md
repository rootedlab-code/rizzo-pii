---
license: apache-2.0
language:
  - it
library_name: transformers
pipeline_tag: token-classification
tags:
  - pii
  - anonymization
  - italian
  - token-classification
base_model: rizzoaiacademy/rizzo-pii-0.3B
---

# rizzo-pii-0.3B-security

Fine-tuning del checkpoint `rizzoaiacademy/rizzo-pii-0.3B` sul **genere documentale
"sicurezza"** — verbali d'incidente, timeline forensi, ticket, estratti di log — a
**tassonomia invariata**: `num_labels` non cambia e il modello resta compatibile con
l'applicazione e con i profili di policy esistenti.

Serve ad anonimizzare documenti **in locale** prima di mandarli a un LLM esterno.

## A cosa serve, e a cosa no

**Serve** a ridurre le PII lasciate in chiaro in documenti italiani di ambito legale e
di sicurezza. Il vincolo che conta e' il **falso negativo**: un dato personale non
mascherato esce dalla macchina, un falso positivo maschera soltanto di piu'.

**Non serve** come garanzia di anonimizzazione completa. Nessun modello di token
classification lo e'. In produzione va affiancato **sempre** alla rete di
regex+checksum, che su codice fiscale, partita IVA, IBAN e carte di credito e' esatta
dove il modello frammenta.

**Non e' stato addestrato** sui tag cyber (IP, hash, wallet, identificativi cloud):
quelli restano coperti dai detector deterministici, che su di essi stanno a recall
0.911 con precision 0.989. Nel dataset di addestramento quei valori compaiono
**senza etichetta**, di proposito: servono a insegnare che una stringa tecnica e' `O`.

## Risultati

Misurati su un **test congelato** di 4.000 righe mai viste durante lo sviluppo,
8.849 entita', eseguito **una volta sola** contro un criterio scritto e depositato
prima di guardare i numeri. Sistema completo (modello + rete regex core), come gira
in produzione.

| | recall | precision | F1 | PII lasciate in chiaro |
|---|--:|--:|--:|--:|
| checkpoint di partenza | 0.806 | 0.738 | 0.770 | 1.721 |
| **questo modello** | **0.858** | **0.795** | **0.826** | **1.254** |

**467 PII in meno** lasciate in chiaro, e 579 falsi positivi in meno.

Confronto **appaiato** (McNemar esatto sulle stesse entita', non intervalli
separati): **559 entita' recuperate contro 92 perse**, p < 1e-6.

Per tag, fra i 19 con almeno 100 entita' nel gold: cinque migliorano in modo
statisticamente distinguibile — `DATE` +254, `DOCID` +69, `BUILDINGNUM` +35,
`CATASTO` +33, `ID_DOC` +18 — quattordici restano invariati, **nessuno peggiora**.

Il guadagno maggiore e' su `DATE`, che il checkpoint di partenza gestiva male fuori
dall'intervallo di date su cui era stato addestrato: troncava l'anno e non
riconosceva il formato ISO.

## Come e' stato addestrato

- Corpus di sicurezza sintetico: 18.805 righe da 196 template, con cap di ripetizione
  per scheletro e riequilibrio dei tag sovrarappresentati.
- **Ripasso** del dominio originale: 10.000 righe. Senza, il modello dimentica —
  misurato: bastano 180 esempi di solo genere sicurezza per far crollare `TARGA` a
  zero.
- 3 epoche, batch efficace 16, learning rate 2e-5, lunghezza massima 2.048 token
  (misurata: la riga piu' lunga dei corpora e' 1.861).

**I dati sintetici non contengono PII reali.** L'LLM scrive solo la prosa con
segnaposto, il codice inietta i valori: cosi' le etichette sono esatte per
costruzione, i checksum sono validi, e nessun dato personale vero puo' essere
rigurgitato. Indirizzi, domini, ASN e MAC vengono **per costruzione** dagli intervalli
riservati alla documentazione (RFC 5737, 1918, 3849, 2606, 5398, 7042), verificato su
ogni riga prodotta.

## Limiti dichiarati

- **Validation solo italiana**: le altre lingue del modello di partenza non sono state
  rimisurate.
- **Dati di addestramento al 100% da template.** Manca l'iniezione in frasi reali, che
  e' la difesa migliore contro l'overfit strutturale: per il genere sicurezza non
  esiste un corpus pubblico utilizzabile.
- Tag deboli che restano tali: `CREDITCARDNUMBER`, `IBAN`, `AMOUNT` e `ZIPCODE` stanno
  sotto 0.5 di recall anche dopo il fine-tuning.
- Il test congelato e' stato speso. Una ricetta successiva va misurata sulla riserva
  da 1.000 righe, e dopo quella serve un campione cieco da una fonte diversa.

## Provenienza

Lavoro derivato da [`Rizzo-AI-Academy/rizzo-pii`](https://github.com/Rizzo-AI-Academy/rizzo-pii)
di Simone Rizzo, da cui vengono il modello di partenza, la tassonomia a 22 tag e la
pipeline di generazione sintetica. Fine-tuning e valutazione di `rootedlab-code`.
