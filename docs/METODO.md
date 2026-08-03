# Metodo — come sapere se un numero significa qualcosa

`GEMELLI.md` elenca le coppie che devono coincidere. `CRITERIO.md` dice quando un
modello sostituisce quello in produzione. `RIADDESTRAMENTO.md` e' la procedura. Questo
file e' quello che tiene insieme i tre, e nasce da una giornata in cui **ogni difetto
costoso aveva la stessa forma**: un numero vero che descriveva qualcosa che non era il
prodotto.

Nessuno di quei difetti produceva un errore. Producevano risultati dall'aria sana.

## 1. Un numero puo' essere vero e inutile insieme

Tre casi misurati, non temuti.

**`TIME`: recall 0.950 sul test congelato, 0 su 9 su un documento vero.** La
validation legale contiene orari nei formati che il modello gestisce; i verbali di
sicurezza usano orari **tondi** — `08:00`, `10:00`, `14:00` — e su quelli falliva
sistematicamente. La popolazione misurata non era la popolazione d'uso.

**`FULLNAME`: 2446 → 2454 sul test congelato, e il prodotto peggiorato.**
`normalize_entities()` in valutazione fonde gli span adiacenti dello stesso tag;
`_merge()` nell'app non lo faceva. La misura e l'app avevano due semantiche diverse
per la stessa operazione, e la misura era quella che rispondeva.

**La sonda che bocciava sul proprio campione.** Prendeva il ripasso da `head -1000`
del pool, dove non c'e' **nessuna** riga con `CATASTO` — e `stratified_rehearsal()`
costruisce l'elenco dei tag da proteggere leggendo il pool, quindi quel tag non
risultava scoperto: risultava inesistente. Per settimane ha bocciato ricette su un
crollo che il suo stesso campione rendeva inevitabile.

**La domanda da porsi davanti a ogni numero buono** non e' «e' corretto?» ma: *su
quale popolazione vale, e quella popolazione e' quella d'uso?*

## 2. L'ordine delle operazioni non e' burocrazia

- **Il criterio si scrive prima del numero che deve giudicare.** Dopo, la scelta di
  quale regola applicare la fa il risultato uscito. Quando la regola B e' stata
  riscritta, e' stato fatto **prima** di guardare l'esito della corsa a 3 epoche, e
  quel dettaglio e' scritto nel documento perche' senza non varrebbe.
- **Il baseline si rimisura sullo stesso hardware, nello stesso momento.** Altrimenti
  il salto include la differenza fra i due apparati e non e' attribuibile al training.
  Riprodurlo cifra per cifra e' anche l'unico modo di sapere che l'ambiente non e'
  cambiato sotto i piedi.
- **Il test congelato si esegue una volta sola**, e prima di eseguirlo si controlla
  che la riserva esista davvero. Qui non esisteva: il documento prometteva le righe
  6000-7000 come secondo tentativo, ed erano gia' dentro il test.
- **La differenza minima rilevabile si calcola prima di lanciare.** A 634 entita' la
  sonda dava tre configurazioni tutte indistinguibili; a 4.346 ne separava due su tre.
  Il campione decideva l'esito prima dei dati.

## 3. Confronto appaiato, non soglie fisse

Due sistemi misurati sulle stesse entita' condividono la maggior parte degli esiti: e'
informazione che due intervalli separati buttano via. Si usa **McNemar esatto** sulle
sole discordanze (`src/training/mcnemar.py`).

Una soglia fissa non calibrata sul campione e' peggio di nessuna soglia. La regola B
chiedeva «non piu' di 0.02 di recall perso» su tag con almeno 100 entita': a 210
entita' l'intervallo di confidenza al 95% e' circa ±0.045, quindi **la soglia stava
dentro il rumore** e poteva scattare per caso.

E il test si applica a **tutti** i tag sopra la soglia, non ai tre che si sospettano
gia': `mcnemar.py --per-tag`. Al primo utilizzo ha mostrato due miglioramenti
statisticamente solidi che non stavo cercando.

## 4. Un documento vero trova cio' che nessun holdout trova

Il modello ha superato un test congelato di 4.000 righe con tutte e tre le regole.
Poi e' stato usato su un verbale d'assessment reale, e in una sola esecuzione sono
emersi:

- 9 orari su 9 lasciati in chiaro (`TIME` senza detector);
- il dominio del committente in chiaro **7 volte**, mentre il file di scope lo
  dichiarava `own` — perche' il suo TLD non era fra i 119 della lista, e il detector
  falliva **in silenzio**;
- gli URL che contenevano lo **stesso** dominio invece mascherati, cioe' un documento
  che sembrava protetto proprio dove non lo era.

L'ultimo e' il piu' istruttivo: **l'evidenza di funzionamento e' cio' che nascondeva
il difetto**. Un fallimento pulito si nota; uno parziale rassicura.

Da qui due principi, entrambi implementati:

- **Cio' che l'analista dichiara vale piu' di cio' che una regex conferma.** I valori
  nel file di scope vengono rilevati per costruzione (`Scope.declared_entities`).
- **Una lista chiusa deve dire quando non sa.** `unknown_tld_tokens()` riporta le
  estensioni a forma di TLD fuori dalla lista. Non indovina: dice dove guardare.

## 5. Le guardie valgono piu' della rilettura

Ogni difetto di questa giornata e' passato sotto gli occhi di qualcuno che stava
guardando proprio quel file. Cio' che li ha fermati non e' stata l'attenzione:

- il **preflight** confronta impronte, TLD, troncamenti e ambiente in pochi secondi,
  e distingue `OK` da **`N/V`** — un controllo che non ha potuto verificare nulla non
  e' un OK;
- il **manifesto sha256** ha permesso di dimostrare che i corpora rigenerati altrove
  erano identici, invece di assumerlo;
- il **pre-commit** ha bloccato **due volte** la stessa modifica: prima il dominio
  reale del committente nei commenti e nei test, poi l'IP reale in un commento. Nessuno
  dei due era visibile rileggendo il diff, e sarebbero finiti in un repo pubblico.

Quando una guardia blocca, la domanda giusta non e' «come la aggiro» ma «cosa ha
visto». `--no-verify` esiste, e ogni volta che serve davvero e' un caso da scrivere
qui dentro.

## 6. Cosa questo metodo NON garantisce

- Non copre il **tradecraft**: nomi di strumenti, VPN, sandbox non sono PII e nessun
  tag li prevede. Un report anonimizzato racconta comunque *come* si lavora.
- Non sostituisce una rilettura umana sui documenti che escono dalla macchina. Riduce
  di molto cosa resta da guardare; non azzera.
- Non dice niente sulle lingue diverse dall'italiano, mai rimisurate.
