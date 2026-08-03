#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fine-tuning del checkpoint gia' rilasciato sui documenti di sicurezza.

NON e' il riaddestramento completo del progetto. Parte dal modello pubblicato, che
conosce gia' i 22 tag, e continua l'addestramento sul nostro dataset a tassonomia
INVARIATA. Percio' `num_labels` non cambia, il checkpoint resta compatibile, e il
costo e' minuti invece di ore.

Serve a chiudere due lacune misurate sul modello rilasciato (vedi il changelog):

  DATE 0.090   addestrato su date 1955-2005, tronca l'anno: su '24/01/2024'
               tagga '24/01/20'; ISO e formato esteso non li vede proprio
  ~2.700       entita' inventate su stringhe tecniche — 866 IBAN, 1.140 TIME,
  falsi        703 ID_DOC prodotti da hash, identificativi cloud e MAC che il
  positivi     modello non ha mai visto

Il secondo e' il motivo per cui il dataset predefinito NON etichetta i valori
cyber: servono come `O`, per insegnare che quelle stringhe non sono niente.

  IL CONTROLLO CHE NON VA SALTATO. Dopo l'addestramento, rimisurare sulla
  validation legale. Aggiungere un genere puo' far DIMENTICARE quello vecchio, e
  un modello che guadagna sui report ma perde sugli atti non e' un miglioramento:
  e' uno scambio, e va visto prima di sostituire qualcosa in produzione.

    python src/training/finetune_security.py \\
        --train dataset/synthetic/synthetic_security_it_plain_train.jsonl \\
        --out   models/rizzo-pii-0.3B-security
"""

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "training"))

BASE_MODEL = "rizzoaiacademy/rizzo-pii-0.3B"
MAX_LEN = 2048        # misurato: la riga piu' lunga di tutti i corpora e' 1861
EPOCHS = 2
BATCH = 8             # con ACCUM 2 il batch EFFICACE resta 16 (§2.3)
ACCUM = 2
LR = 2e-5

# La testa di classificazione di mmBERT non e' il solo `classifier`: fra l'ultimo
# strato dell'encoder e la proiezione finale c'e' `head` (dense + norm). Agganciare
# il solo `classifier` lascia addestrabile lo 0,011% dei pesi — e' linear probing,
# non "addestra la testa".
HEAD_PREFIXES = ("head.", "classifier.")


def bio_of(rec, label2id, tag_map, drop):
    """BIO della riga, rimappato nella tassonomia del modello.

    I dati grezzi hanno GIVENNAME/SURNAME, il modello conosce FULLNAME: senza la
    rimappatura si addestrerebbe su etichette che non esistono nella sua testa, e
    ogni nome diventerebbe rumore."""
    out = []
    for label in rec["bio_labels"]:
        if label == "O" or "-" not in label:
            out.append("O")
            continue
        prefix, tipo = label.split("-", 1)
        tipo = tag_map.get(tipo, tipo)
        nuovo = "O" if tipo in drop else f"{prefix}-{tipo}"
        out.append(nuovo if nuovo in label2id else "O")
    return out


def tags_of(rec, tag_map, drop):
    """Tipi presenti in una riga, gia' rimappati nella tassonomia del modello."""
    out = set()
    for label in rec["bio_labels"]:
        if label.startswith("B-"):
            tipo = tag_map.get(label[2:], label[2:])
            if tipo not in drop:
                out.add(tipo)
    return out


def head_parameters(nomi):
    """Divide i nomi dei parametri fra testa di classificazione ed encoder.

    Ritorna `(agganciati, orfani)`: i nomi che restano addestrabili, e i prefissi di
    HEAD_PREFIXES che non hanno trovato alcun riscontro. Un prefisso orfano e' il
    modo silenzioso in cui questa leva si guasta — cambia l'architettura di base, il
    prefisso non aggancia piu' nulla, e la corsa parte lo stesso addestrando un
    decimo di cio' che dovrebbe. Va visto prima di pagare le ore di GPU (§2.5)."""
    nomi = list(nomi)     # scorso una volta per prefisso: un generatore si esaurirebbe
    agganciati, orfani = [], []
    for prefisso in HEAD_PREFIXES:
        trovati = [n for n in nomi if n.startswith(prefisso)]
        if trovati:
            agganciati.extend(trovati)
        else:
            orfani.append(prefisso)
    return agganciati, orfani


def quante_di_ripasso(n_nuove, ratio, n_pool):
    """Righe di ripasso da usare e righe richieste dal rapporto: `(quante, richieste)`.

    Le due divergono quando il pool si esaurisce, e da quel punto in poi
    `--rehearsal-ratio` **e' inerte**: alzarlo non cambia niente, e nemmeno
    `--rehearsal-strategy`, perche' prendendo tutto il pool non c'e' piu' nulla da
    selezionare. E' successo davvero nella corsa a scala piena — 18.805 x 4 = 75.220
    richieste da un pool di 10.000 — mentre la stessa leva veniva tarata sulla sonda,
    dove il pool non si esaurisce e quindi funziona. Chi legge il comando vede due
    opzioni che a scala piena non sono collegate a niente."""
    richieste = int(n_nuove * ratio)
    return min(n_pool, richieste), richieste


def scheda_corsa(args, righe, esempi, ripasso_righe):
    """Il record di cio' che la corsa ha davvero eseguito, salvato in finetune.json.

    Parte da `vars(args)`, cioe' registra **ogni** leva della riga di comando per
    costruzione: una leva nuova non puo' essere dimenticata qui, che e' la stessa
    garanzia di un test ma senza il test. Ai valori dichiarati aggiunge quelli
    derivati che non si leggono da nessuna singola opzione — primo fra tutti il
    batch EFFICACE, senza il quale `batch: 8` di due corse con accumulo diverso si
    legge come la stessa configurazione (§2.3)."""
    return {**vars(args),
            "batch_efficace": args.batch * args.accum,
            "righe": righe,
            "esempi": esempi,
            "ripasso_righe": ripasso_righe}


def stratified_rehearsal(pool, quante, nuove, tag_map, drop, seed=42):
    """Sceglie le righe di ripasso per coprire i tag che i dati NUOVI non contengono.

    Il campionamento casuale non basta perche' il problema non e' la quantita' totale
    di ripasso ma la copertura per tag: misurato, i tag che degradano nel fine-tuning
    (CATASTO, ID_DOC, TIME, DOCID, TARGA) sono esattamente quelli che i documenti di
    sicurezza non nominano mai. Un verbale di incidente non contiene dati catastali:
    l'assenza e' la realta' del dominio, non un difetto da correggere nei dati nuovi.

    Percio' il ripasso viene scelto a turno fra i tag mancanti, dal piu' raro nel pool
    al piu' comune: cosi' un tag con poche righe disponibili non viene schiacciato da
    uno che ne ha migliaia."""
    import random

    presenti = set()
    for rec in nuove:
        presenti |= tags_of(rec, tag_map, drop)

    per_tag = collections.defaultdict(list)
    for i, rec in enumerate(pool):
        for t in tags_of(rec, tag_map, drop):
            per_tag[t].append(i)

    mancanti = sorted((t for t in per_tag if t not in presenti),
                      key=lambda t: len(per_tag[t]))
    print(f"  tag assenti dai dati nuovi: {', '.join(mancanti) or 'nessuno'}")

    rng = random.Random(seed)
    for indici in per_tag.values():
        rng.shuffle(indici)

    scelti, cursore = [], collections.Counter()
    visti = set()
    # giro a turno: una riga per tag mancante, dal piu' raro; poi si ricomincia
    while len(scelti) < quante and mancanti:
        progresso = False
        for t in mancanti:
            if len(scelti) >= quante:
                break
            lista = per_tag[t]
            while cursore[t] < len(lista):
                i = lista[cursore[t]]
                cursore[t] += 1
                if i not in visti:
                    visti.add(i)
                    scelti.append(pool[i])
                    progresso = True
                    break
        if not progresso:
            break

    # il resto si completa a caso, per non impoverire i tag comuni
    if len(scelti) < quante:
        resto = [r for i, r in enumerate(pool) if i not in visti]
        rng.shuffle(resto)
        scelti += resto[:quante - len(scelti)]
    return scelti


def build_dataset(rows, tokenizer, label2id, tag_map, drop, max_len=MAX_LEN):
    """Tokenizza allineando le etichette ai subword: solo il PRIMO subword di ogni
    parola porta l'etichetta, gli altri sono ignorati (-100). E' la convenzione di
    Hugging Face e quella con cui il modello e' stato addestrato la prima volta."""
    import torch

    esempi = []
    senza_entita = 0
    for rec in rows:
        bio = bio_of(rec, label2id, tag_map, drop)
        enc = tokenizer(rec["tokens"], is_split_into_words=True,
                        truncation=True, max_length=max_len)
        etichette, precedente = [], None
        for wid in enc.word_ids():
            if wid is None:
                etichette.append(-100)
            elif wid != precedente:
                etichette.append(label2id.get(bio[wid], label2id["O"]))
            else:
                etichette.append(-100)
            precedente = wid
        # Le righe interamente `O` RESTANO. Una versione precedente le scartava come
        # "righe che non insegnano nulla": e' falso per questo dataset, dove 8
        # template su 27 sono deliberatamente privi di PII e insegnano che un
        # indirizzo IP, un hash e un identificativo cloud sono `O`. Sono il 15,8% del
        # corpus bilanciato, e sono la meta' del motivo per cui il fine-tuning esiste
        # — l'altra lacuna misurata sono ~2.700 entita' inventate su stringhe
        # tecniche. Scartarle addestrava contro l'obiettivo dichiarato.
        if all(e in (-100, label2id["O"]) for e in etichette):
            senza_entita += 1
        esempi.append({"input_ids": enc["input_ids"],
                       "attention_mask": enc["attention_mask"],
                       "labels": etichette})
    if senza_entita:
        print(f"  {senza_entita} righe interamente 'O' incluse: insegnano il negativo")

    class Dataset(torch.utils.data.Dataset):
        def __len__(self):
            return len(esempi)

        def __getitem__(self, i):
            return esempi[i]

    return Dataset()


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--train", required=True, help=".jsonl di addestramento")
    ap.add_argument("--rehearsal", default=None,
                    help="ripasso: .jsonl del dominio ORIGINALE da mescolare. Senza, "
                         "il modello DIMENTICA — misurato: bastano 180 esempi di solo "
                         "genere sicurezza per far scendere il legale da 0.822 a 0.763 "
                         "e azzerare TARGA")
    ap.add_argument("--rehearsal-strategy", choices=("random", "stratified"),
                    default="random",
                    help="'stratified' sceglie le righe di ripasso per coprire i tag "
                         "che i dati nuovi NON contengono — sono quelli che degradano")
    ap.add_argument("--rehearsal-ratio", type=float, default=1.0,
                    help="quante righe di ripasso per ogni riga nuova (default 1.0)")
    ap.add_argument("--out", required=True, help="dove salvare il modello")
    ap.add_argument("--base", default=BASE_MODEL)
    ap.add_argument("--epochs", type=float, default=EPOCHS)
    ap.add_argument("--batch", type=int, default=BATCH)
    ap.add_argument("--freeze-encoder", action="store_true",
                    help="congela l'encoder e addestra la sola testa di "
                         f"classificazione ({' + '.join(HEAD_PREFIXES)}), ~0,2% dei "
                         "pesi. E' la leva piu' forte contro la dimenticanza — il "
                         "modello non puo' scordare cio' che non puo' modificare — "
                         "al prezzo di imparare meno")
    ap.add_argument("--accum", type=int, default=ACCUM,
                    help="accumulo: batch EFFICACE = batch x accum. Tienilo costante "
                         "quando confronti varianti, altrimenti cambi il numero di "
                         "passi di ottimizzazione e stai confrontando due esperimenti")
    ap.add_argument("--lr", type=float, default=LR)
    ap.add_argument("--max-len", type=int, default=MAX_LEN)
    return ap


def main():
    args = build_parser().parse_args()

    import torch
    from transformers import (AutoModelForTokenClassification, AutoTokenizer,
                              DataCollatorForTokenClassification, Trainer,
                              TrainingArguments)
    from evaluate_entities import DROP_TYPES, TAG_MAP, load

    print(f"carico {args.base} ...")
    tokenizer = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForTokenClassification.from_pretrained(args.base)
    label2id = model.config.label2id
    print(f"  {len(label2id)} etichette BIO, num_labels INVARIATO")
    if args.freeze_encoder:
        agganciati, orfani = head_parameters(n for n, _ in model.named_parameters())
        # §2.5: asserire cio' che DEVE essere addestrabile, non solo cio' che non deve.
        # Un prefisso che non aggancia nulla non ferma la corsa da solo: la lascia
        # partire, girare per ore e costare, e si scopre alla misura finale.
        if orfani:
            sys.exit(f"ERRORE: --freeze-encoder non ha trovato parametri per "
                     f"{', '.join(orfani)} in {args.base}. L'architettura non e' "
                     f"quella attesa: la corsa addestrerebbe meno di quanto credi.")
        agganciati = set(agganciati)
        for nome, par in model.named_parameters():
            par.requires_grad = nome in agganciati
        addestrabili = sum(p_.numel() for n, p_ in model.named_parameters()
                           if n in agganciati)
        totali = sum(p_.numel() for p_ in model.parameters())
        print(f"  encoder congelato: {addestrabili:,}/{totali:,} parametri addestrabili "
              f"({addestrabili/totali:.3%}) — {', '.join(sorted(agganciati))}")
    print(f"  GPU: {torch.cuda.is_available()}")

    rows = load(args.train)
    print(f"{len(rows)} righe da {args.train}")
    quante = 0
    if args.rehearsal:
        import random
        ripasso = load(args.rehearsal)
        quante, richieste = quante_di_ripasso(len(rows), args.rehearsal_ratio,
                                              len(ripasso))
        if richieste > len(ripasso):
            satura = len(ripasso) / len(rows)
            print(f"  ATTENZIONE: --rehearsal-ratio {args.rehearsal_ratio:g} chiede "
                  f"{richieste} righe da un pool di {len(ripasso)}: le prende TUTTE.\n"
                  f"  Sopra ratio {satura:.2f} la leva e' INERTE, e con essa "
                  f"--rehearsal-strategy (non c'e' piu' nulla da selezionare).\n"
                  f"  Per pesare di piu' il dominio originale serve un pool piu' "
                  f"grande, non un rapporto piu' alto.")
        if args.rehearsal_strategy == "stratified":
            scelte = stratified_rehearsal(ripasso, quante, rows, TAG_MAP, DROP_TYPES)
        else:
            random.Random(42).shuffle(ripasso)
            scelte = ripasso[:quante]
        rows = rows + scelte
        random.Random(42).shuffle(rows)
        print(f"  + {quante} righe di ripasso da {args.rehearsal} -> {len(rows)} totali")
    else:
        print("  ATTENZIONE: nessun ripasso. Il modello DIMENTICHERA' il dominio "
              "originale;\n  misurato: 180 esempi bastano a far scendere il legale "
              "da 0.822 a 0.763.")
    ds = build_dataset(rows, tokenizer, label2id, TAG_MAP, DROP_TYPES, args.max_len)
    print(f"  {len(ds)} esempi di addestramento")

    out = Path(args.out)
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(out / "_run"),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch,
            gradient_accumulation_steps=args.accum,
            learning_rate=args.lr,
            warmup_ratio=0.1,
            logging_steps=50,
            save_strategy="no",
            report_to=[],
            fp16=torch.cuda.is_available(),
        ),
        train_dataset=ds,
        data_collator=DataCollatorForTokenClassification(tokenizer),
    )
    trainer.train()

    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    (out / "finetune.json").write_text(
        json.dumps(scheda_corsa(args, len(rows), len(ds), quante), indent=2), "utf-8")
    print(f"\nsalvato -> {out}")
    print("\nORA IL CONTROLLO CHE NON VA SALTATO:")
    print("  1) rimisura sul genere sicurezza (deve salire)")
    print("  2) rimisura sulla validation legale (NON deve scendere)")
    print("  Se il legale scende, non hai aggiunto una capacita': ne hai barattata una.")


if __name__ == "__main__":
    main()
