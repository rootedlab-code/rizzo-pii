---
license: mit
language:
  - it
task_categories:
  - token-classification
task_ids:
  - named-entity-recognition
tags:
  - pii
  - anonymization
  - italian
  - synthetic
  - security
  - cybersecurity
  - gdpr
size_categories:
  - 10K<n<100K
pretty_name: "rizzo-pii security IT — corpus sintetico del genere sicurezza"
configs:
  - config_name: plain
    default: true
    data_files:
      - split: train
        path: synthetic_security_it_plain_train.jsonl
      - split: eval
        path: synthetic_security_it_plain_eval.jsonl
  - config_name: bilanciato
    data_files:
      - split: train
        path: security_train_bilanciato.jsonl
  - config_name: cyberlabeled
    data_files:
      - split: train
        path: synthetic_security_it_cyberlabeled.jsonl
      - split: eval
        path: synthetic_security_it_cyberlabeled_eval.jsonl
---

# rizzo-pii security IT — corpus sintetico del genere "sicurezza"

Corpus **sintetico italiano** per la **token classification di PII** su documenti di sicurezza:
verbali d'incidente, timeline forensi, ticket, estratti di log.

Serve ad addestrare un modello che anonimizzi quei documenti **in locale**, prima di mandarli a un
LLM esterno. È il dataset con cui è stato addestrato
[`dr3x1/rizzo-pii-0.3B-security`](https://huggingface.co/dr3x1/rizzo-pii-0.3B-security).

**Non contiene nessuna PII reale.** Nessun dato personale vero, nessun indicatore di compromissione
di un caso reale, nessun dato d'ingaggio: ogni valore è generato da codice a partire dagli spazi
riservati alla documentazione. Il come sta in [Costruzione](#costruzione).

---

## Il problema che risolve

Un modello di anonimizzazione addestrato su prosa legale italiana peggiora sui documenti di
sicurezza **proprio dove è insostituibile** — sui tag che una rete di regex non può coprire. Due
lacune misurate sul checkpoint di partenza, su 31 template mai visti:

| lacuna | numero | causa |
|---|---|---|
| `DATE` a recall **0.090** | su `24/01/2024` etichettava `24/01/20` | addestrato su date fra 1955 e 2005, l'intervallo delle date di nascita. ISO: 0.000 |
| **~2.700 falsi positivi** | 866 `IBAN`, 1.140 `TIME`, 703 `ID_DOC` | inventati su hash, identificativi cloud e indirizzi MAC mai visti |

Il secondo è il più interessante: il modello vedeva una stringa tecnica mai incontrata e la
riconduceva alla forma nota più vicina. Un hash esadecimale lungo «assomiglia» a un IBAN, se in
addestramento hai visto solo atti giudiziari.

## La scelta centrale: i valori cyber compaiono SENZA etichetta

Nella variante predefinita (`plain`) gli indirizzi IP, gli hash, i MAC, gli ASN, le risorse cloud
e le chiavi **stanno nella prosa ma sono etichettati `O`** — cioè "non è un'entità".

Non è una dimenticanza: **l'assenza dell'etichetta è il segnale di addestramento.** Fa tre cose
insieme:

1. **insegna il registro tecnico**, così il modello smette di trattare il documento come alieno —
   ed è da qui che `DATE` risale, perché questo corpus contiene date moderne e ISO;
2. **insegna esplicitamente che una stringa tecnica è `O`**, che è l'antidoto diretto alle ~2.700
   entità inventate;
3. **lascia `num_labels` invariato**, quindi il checkpoint resta compatibile con l'applicazione
   esistente, con la sua tassonomia e con i suoi profili. Minuti di GPU, non ore.

Corollario che sembra un dettaglio: **le righe interamente `O` restano nel corpus** — sono il
15,8% del bilanciato. "Pulire" il dataset scartandole addestrerebbe contro l'obiettivo dichiarato.

I tag cyber **veri** non li fa il modello: li fa una rete di detector deterministici
(regex + validatori, `ipaddress` per gli IP, Base58Check per i wallet), che su quei tag sta a
**recall 0.911 con precision 0.989**. La variante `cyberlabeled` esiste per poter *ricalcolare
quel campione da battere*, non perché sia la strada consigliata: etichettare quei tag cambia
`num_labels` e impone il riaddestramento completo.

## I file

| file | righe | token/riga | righe tutte `O` | a cosa serve |
|---|--:|--:|--:|---|
| `security_train_bilanciato.jsonl` | 18.805 | 195 | 15,8% | **il corpus di addestramento vero**: cap di ripetizione per scheletro e riequilibrio dei tag |
| `synthetic_security_it_plain_train.jsonl` | 26.851 | 213 | 11,1% | il pool grezzo da cui viene il bilanciato |
| `synthetic_security_it_plain_eval.jsonl` | 1.113 | 188 | 15,3% | valutazione, da **template disgiunti** |
| `synthetic_security_it_cyberlabeled.jsonl` | 16.795 | 213 | 0% | variante con i tag cyber **etichettati** |
| `synthetic_security_it_cyberlabeled_eval.jsonl` | 1.053 | 209 | 0% | la sua valutazione |
| `security_templates.json` | 169 template | — | — | la banca dei template, per rigenerare tutto |

Impronte SHA-256 dei due file usati per l'addestramento pubblicato:

```
security_train_bilanciato.jsonl            cbcc89e8aa0bde2d1fd79f9a2599c8ba2c68a7279cd9ecc7eb9b5dd6831a3ea9
synthetic_security_it_plain_eval.jsonl     a6e81738ef31b86e583292246f85fca47e9855db381223971ffc69663a3485e9
```

## Formato

Una riga JSON per esempio, **sette campi**. Il corpus è distribuito in **due viste della stessa
annotazione** — testo con offset di carattere, e token con etichette BIO — così che non serva
convertire da una all'altra.

| campo | tipo | cosa contiene |
|---|---|---|
| `source_text` | `str` | **il testo esatto**, con i newline veri. È la vista autorevole |
| `entities` | `list[dict]` | `{value, label, start, end}` — offset di **carattere** su `source_text` |
| `tokens` | `list[str]` | token separati da spazi e punteggiatura (**non** WordPiece) |
| `bio_labels` | `list[str]` | stessa lunghezza di `tokens`, schema BIO |
| `template_id` | `int` | quale template ha prodotto la riga: serve per verificare lo split |
| `language` | `str` | sempre `"it"` |
| `meta` | `dict` | `{contributor, seed, synthetic, generator_version, genre, cyber_labeled}` |

> **Non ricostruire il testo dai token.** `source_text` c'è apposta. Ricomporre una frase unendo
> token con uno spazio è una trappola classica di questi corpora, e su un dataset tokenizzato a
> sotto-parole l'effetto è **controintuitivo: gonfia i risultati**, perché gli identificatori
> lunghi arrivano al modello già spezzati esattamente sui confini attesi dal gold. Qui i token
> non sono WordPiece e il problema non si pone, ma la vista a offset resta quella da usare.

Le due viste sono coerenti per costruzione: `source_text[start:end] == value` su ogni entità.

Esempio della prosa generata (una riga del `plain_eval`):

```
Escalation : il caso passa a Stefano Fabbri ( gaetano . gentile @ example . it ,
+ 39 375 4694634 ) per la verifica dell ' esposizione della chiave AKIA<16 car.> .
```

| valore | etichetta |
|---|---|
| `Stefano` | `GIVENNAME` |
| `Fabbri` | `SURNAME` |
| `gaetano.gentile@example.it` | `EMAIL` |
| `+39 375 4694634` | `TELEPHONENUM` |
| **`AKIA<16 car.>`** | **`O` — non compare fra le entità** |

L'ultima riga è la scelta centrale in un esempio: la chiave in stile AWS **c'è nel testo** e non
è annotata. Nella variante `cyberlabeled` la stessa stringa è etichettata `CLOUDID`.

La chiave è abbreviata **qui nella scheda**, non nel corpus: nei file compare per intero, ed è un
valore generato — la forma di una chiave AWS riempita di caratteri casuali, senza alcun
corrispettivo reale.

## Tassonomia

- **`plain`**: 12 tag — `DATE`, `ORG`, `CITY`, `EMAIL`, `GIVENNAME`, `SURNAME`, `AMOUNT`,
  `TELEPHONENUM`, `STREET`, `BUILDINGNUM`, `ZIPCODE`, `PROVINCE` (44.727 entità nel bilanciato).
- **`cyberlabeled`**: i precedenti più `IP`, `DOMAIN`, `URL`, `HASH`, `MAC`, `ASN`, `WALLET`,
  `CLOUDID`, `PATH`, `USER`.

I nomi dei tag seguono la tassonomia a 22 tag del progetto di partenza, così che il corpus si
possa mescolare con i suoi senza rimappature.

## Costruzione

**«LLM autore, codice etichettatore».** L'LLM scrive *soltanto* la prosa con segnaposto `{SLOT}`;
è il codice a iniettare i valori. Risolve tre problemi insieme:

- le etichette BIO sono **esatte per costruzione** — sappiamo dove abbiamo iniettato, non lo
  stiamo indovinando;
- i checksum sono **matematicamente validi** (CF, PIVA, IBAN);
- **nessuna PII reale può essere rigurgitata**, perché all'LLM non ne è mai stata mostrata una.

**Ogni valore tecnico viene dagli spazi riservati alla documentazione, per costruzione**, e c'è un
test che lo verifica su decine di migliaia di campioni generati:

| spazio | RFC |
|---|---|
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 |
| `10/8`, `172.16/12`, `192.168/16` | RFC 1918 |
| `2001:db8::/32` | RFC 3849 |
| `example.com`, `example.it`, `.test`, `.invalid` | RFC 2606 |
| ASN `64496-64511`, `65536-65551` | RFC 5398 |
| MAC `00:00:5E:00:53:xx` | RFC 7042 |

**Template:** 196 in tutto — 27 scritti a mano, 169 in banca. Lo split train/eval è deciso
dall'**impronta** di ogni template, non dalla sua posizione, quindi resta stabile quando la banca
cresce. Verificato su questi file: **0 template condivisi**, e **0 scheletri condivisi** fra
20.923 (train) e 861 (eval). Se un giorno non desse zero ci sarebbe leakage, e qualunque numero
misurato dopo sarebbe privo di valore.

**Bilanciamento:** cap di ripetizione per scheletro e riequilibrio dei tag sovrarappresentati.
Serve perché 196 template ripetuti decine di migliaia di volte insegnano la *struttura* invece
dell'entità.

## Riprodurlo

Il codice sta su [github.com/rootedlab-code/rizzo-pii](https://github.com/rootedlab-code/rizzo-pii/tree/dev)
(branch `dev`).

```bash
python src/data_pipeline/generate_cyber_pii.py -n  1200 --split eval
python src/data_pipeline/generate_cyber_pii.py -n 30000 --split train \
    --max-tag-repeat 2 --out dataset/synthetic/security_train_bilanciato.jsonl

# la variante con i tag cyber etichettati (cambia num_labels)
python src/data_pipeline/generate_cyber_pii.py -n 30000 --split train --label-cyber
```

La generazione **non richiede una chiave LLM**: usa la banca di template inclusa. Serve solo per
ampliarla (`--gemini`, oppure qualunque endpoint OpenAI-compatible).

## Come è stato usato

Fine-tuning del checkpoint `rizzoaiacademy/rizzo-pii-0.3B` a **tassonomia invariata**: corpus
bilanciato (18.805 righe) più **10.000 righe di ripasso** del dominio originale, 3 epoche, batch
efficace 16, learning rate 2e-5, `max_len` 2048. ~26 minuti su una NVIDIA L4.

Il ripasso non è opzionale: **180 esempi di solo genere sicurezza bastano a portare `TARGA` a
zero**. E il numero di epoche non è una scelta di comodo — `ID_DOC` e `ZIPCODE` si muovono in
direzioni opposte su quell'asse (dimenticanza contro interferenza), e 3 è il punto in cui nessun
tag decisivo arretra.

Risultato, su un campione cieco di 1.000 righe con criterio depositato prima della misura:
recall **0.737 → 0.808**, precision 0.670 → 0.742. Dettagli, limiti e confronto appaiato nella
[scheda del modello](https://huggingface.co/dr3x1/rizzo-pii-0.3B-security).

## Limiti dichiarati

- **I dati sono al 100% da template.** Manca l'iniezione delle entità in **frasi reali**, che è la
  difesa migliore contro l'overfit strutturale: per il genere sicurezza non esiste un corpus
  pubblico utilizzabile. Il cap per scheletro riduce la ripetitività, non la elimina.
- **La distribuzione degli IP è irrealistica per costruzione**: tre `/24` documentali più RFC 1918.
  Con `cyberlabeled` un modello imparerebbe che «IP» significa «comincia con quei prefissi». Lo
  split sui valori misura quanto pesa, non lo elimina.
- **Solo italiano.** Non è stato validato su altre lingue.
- **Non copre il tradecraft**: nomi di strumenti, VPN, sandbox non sono PII e nessun tag li
  prevede. Un report anonimizzato racconta comunque *come* si lavora.
- **Il genere è documentale, non operativo**: la prosa imita verbali e ticket, non il traffico o i
  log grezzi.

## Provenienza e licenza

**MIT.**

Da [`Rizzo-AI-Academy/rizzo-pii`](https://github.com/Rizzo-AI-Academy/rizzo-pii) di **Simone
Rizzo** vengono la tassonomia dei tag, l'architettura della pipeline di generazione sintetica e il
principio «LLM autore, codice etichettatore» su cui questo corpus è costruito. Copyright del
progetto originale © 2026 Simone Rizzo — Rizzo AI Academy.

Genere documentale "sicurezza", template, spazi documentali e bilanciamento: `rootedlab-code`.

Catena del modello addestrato su questo corpus:
[`jhu-clsp/mmBERT-base`](https://huggingface.co/jhu-clsp/mmBERT-base) →
[`rizzoaiacademy/rizzo-pii-0.3B`](https://huggingface.co/rizzoaiacademy/rizzo-pii-0.3B) →
[`dr3x1/rizzo-pii-0.3B-security`](https://huggingface.co/dr3x1/rizzo-pii-0.3B-security).
