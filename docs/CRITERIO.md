# Criterio di accettazione — scritto PRIMA di guardare il test congelato

La validation legale usata finora (righe 0-2000) e' stata eseguita **quattro volte**
adattando la ricetta a ogni giro: ripasso assente, casuale 1:1, casuale 4:1, lr 5e-6,
stratificato. Il riuso adattivo di un holdout ne consuma la validita' anche senza
barare (Dwork et al., Science 2015), quindi tutti i numeri prodotti su quelle righe
vanno letti come **esplorativi**, non come misura finale.

Il test congelato e' `dataset/validation/test_congelato_legale.jsonl` — righe
4000-6000 della validation, **mai guardate**. Impronta in `test_congelato.sha256`.

## Regole

1. Si esegue **una volta sola**, sul candidato scelto usando le righe 0-2000.
2. Il criterio e' scritto qui sotto e non si tocca dopo aver visto il risultato.
3. Se il candidato fallisce, non si sceglie il secondo classificato sullo stesso
   test: si torna alle righe 0-2000, si cambia ricetta, e serve un nuovo test
   congelato (righe 6000-7000, che restano).

## Criterio

Il modello addestrato si puo' sostituire a quello attuale **se e solo se**, sul test
congelato e con la rete regex core attiva come in produzione:

- **A.** McNemar appaiato sulle entita' del gold: p < 0.05 **e** piu' entita'
  recuperate che perse. Non il micro: due configurazioni con micro 0.793 e 0.797 sono
  risultate una indistinguibile dalla baseline (p = 0.280) e l'altra un miglioramento
  reale (p = 0.006).
- **B.** Nessun tag con almeno 100 entita' nel gold perde piu' di **0.02** di recall.
  I tag sotto 100 entita' si riportano ma non decidono: l'intervallo e' troppo largo.
- **C.** `CATASTO`, `ID_DOC` e `ZIPCODE` — i tre che degradano piu' spesso — non
  scendono sotto la baseline. Sono i canarini.

Se A passa ma B o C no, l'esito e' **uno scambio**, non un miglioramento, e la
decisione se accettarlo e' dell'utente, non automatica.

## Cosa questo criterio NON copre

- La resa sul genere sicurezza. Va misurata, ma non decide la sostituzione: il
  modello attuale e' in produzione sul dominio legale, e il vincolo e' non peggiorarlo.
- La differenza minima rilevabile non e' stata calcolata prima (§3.11): con ~4.300
  entita' appaiate e le discordanze osservate (60-130), il disegno ha potuto
  distinguere effetti di quell'ordine, ma non e' stato pre-registrato.
