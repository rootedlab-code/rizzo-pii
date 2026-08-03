# Criterio di accettazione — scritto PRIMA di guardare il test congelato

La validation legale usata finora (righe 0-2000) e' stata eseguita **quattro volte**
adattando la ricetta a ogni giro: ripasso assente, casuale 1:1, casuale 4:1, lr 5e-6,
stratificato. Il riuso adattivo di un holdout ne consuma la validita' anche senza
barare (Dwork et al., Science 2015), quindi tutti i numeri prodotti su quelle righe
vanno letti come **esplorativi**, non come misura finale.

Il test congelato e' `dataset/validation/test_congelato_legale.jsonl`: **4.000 righe,
posizioni 2000-5999 della validation**, mai guardate. Impronta in
`test_congelato.sha256`.

La riserva e' `dataset/validation/test_riserva_legale.jsonl`: **1.000 righe, posizioni
6000-6999**, mai guardate nemmeno da questo criterio. Impronta in
`test_riserva.sha256`.

> **Ritagliate il 2026-08-03, prima di eseguire alcunche'.** Il file conteneva
> **5.000** righe — le posizioni 2000-6999, cioe' tutto il complemento delle
> esplorative — mentre questo documento dichiarava «righe 4000-6000» e prometteva
> come riserva le «righe 6000-7000, che restano». Quelle righe non restavano: erano
> gia' dentro il test congelato. Eseguendolo com'era, un fallimento avrebbe lasciato
> **zero** campioni ciechi per la ricetta successiva.
>
> Impronta del file originale da 5.000 righe, per tracciabilita':
> `17e88bd7167e80e35a7c408c3230a817758a909a3127bad8b15f3121bde35916`.
>
> Sovrapposizione fra congelato e righe 0-2000: **1 riga su 5.000**, un testo
> duplicato dentro la validation stessa. Misurata, non assunta.

## Regole

1. Si esegue **una volta sola**, sul candidato scelto usando le righe 0-2000.
2. Il criterio e' scritto qui sotto e non si tocca dopo aver visto il risultato.
3. Se il candidato fallisce, non si sceglie il secondo classificato sullo stesso
   test: si torna alle righe 0-2000, si cambia ricetta, e si spende **la riserva**.
   Dopo quella non c'e' altro: un terzo tentativo richiede un campione cieco da una
   fonte diversa, non un altro ritaglio di questa validation.

## Criterio

Il modello addestrato si puo' sostituire a quello attuale **se e solo se**, sul test
congelato e con la rete regex core attiva come in produzione:

- **A.** McNemar appaiato sulle entita' del gold: p < 0.05 **e** piu' entita'
  recuperate che perse. Non il micro: due configurazioni con micro 0.793 e 0.797 sono
  risultate una indistinguibile dalla baseline (p = 0.280) e l'altra un miglioramento
  reale (p = 0.006).
- **B.** Nessun tag con almeno 100 entita' nel gold peggiora in modo **statisticamente
  distinguibile**: McNemar appaiato sulle sole entita' di quel tag, p < 0.05 **e** piu'
  perse che recuperate. I tag sotto 100 entita' si riportano ma non decidono.

      python src/training/mcnemar.py <gold> --a <baseline> --b <candidato> \
          --limit <N> --labels ID_DOC

- **C.** `CATASTO`, `ID_DOC` e `ZIPCODE` — i tre che degradano piu' spesso — si
  guardano per primi. Sono i canarini, ma decidono **con la stessa regola B**: un
  canarino con meno di 100 entita' segnala, non boccia.

I conteggi che contano sono quelli **del test congelato**, non quelli delle righe
0-2000: un tag puo' stare sopra la soglia in un campione e sotto nell'altro.

### Perche' B non e' piu' una soglia fissa (riscritta il 2026-08-03)

Diceva: «nessun tag sopra 100 entita' perde piu' di **0.02** di recall». A 210 entita'
l'intervallo di confidenza al 95% sul recall e' circa ±0.045: **la soglia stava dentro
il rumore**. Una regola che si puo' far scattare per caso, prima o poi boccia un
modello buono o ne accetta uno cattivo, e in entrambi i casi il verdetto lo decide il
campione invece del modello.

Misurato sulle righe 0-2000, il test appaiato e la soglia fissa **non concordano**:

| tag | gold | recall | soglia 0.02 | McNemar appaiato |
|---|--:|--:|---|---|
| `ID_DOC` | 210 | 0.905 → 0.857 | bocciato (−0.048) | 12 perse / 2 recuperate, **p = 0.013** → bocciato |
| `ZIPCODE` | 87 | 0.379 → 0.322 | bocciato (−0.057) | 9 perse / 4 recuperate, **p = 0.267** → non distinguibile |

Su `ZIPCODE` la soglia bocciava una differenza che vale nove entita' su ottantasette e
che il test non sa separare dal caso. Su `ID_DOC` le due regole concordano — ma
concordare su un caso non rende affidabile una soglia che non e' calibrata sulla
taglia del campione.

**Questa riscrittura e' avvenuta PRIMA di guardare il risultato che deve giudicare.**
E' l'unico momento in cui si puo' cambiare un criterio senza svuotarlo: dopo, la
scelta di quale regola applicare la fa il numero che e' uscito.

Se A passa ma B o C no, l'esito e' **uno scambio**, non un miglioramento, e la
decisione se accettarlo e' dell'utente, non automatica.

## Cosa questo criterio NON copre

- La resa sul genere sicurezza. Va misurata, ma non decide la sostituzione: il
  modello attuale e' in produzione sul dominio legale, e il vincolo e' non peggiorarlo.
- La differenza minima rilevabile non e' stata calcolata prima (§3.11): con ~4.300
  entita' appaiate e le discordanze osservate (60-130), il disegno ha potuto
  distinguere effetti di quell'ordine, ma non e' stato pre-registrato.
