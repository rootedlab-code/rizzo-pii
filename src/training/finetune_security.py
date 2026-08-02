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
MAX_LEN = 512
EPOCHS = 2
BATCH = 16
LR = 2e-5


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


def build_dataset(rows, tokenizer, label2id, tag_map, drop):
    """Tokenizza allineando le etichette ai subword: solo il PRIMO subword di ogni
    parola porta l'etichetta, gli altri sono ignorati (-100). E' la convenzione di
    Hugging Face e quella con cui il modello e' stato addestrato la prima volta."""
    import torch

    esempi = []
    scartate = 0
    for rec in rows:
        bio = bio_of(rec, label2id, tag_map, drop)
        enc = tokenizer(rec["tokens"], is_split_into_words=True,
                        truncation=True, max_length=MAX_LEN)
        etichette, precedente = [], None
        for wid in enc.word_ids():
            if wid is None:
                etichette.append(-100)
            elif wid != precedente:
                etichette.append(label2id.get(bio[wid], label2id["O"]))
            else:
                etichette.append(-100)
            precedente = wid
        if all(e in (-100, label2id["O"]) for e in etichette):
            scartate += 1          # righe senza alcuna entita': non insegnano nulla
            continue
        esempi.append({"input_ids": enc["input_ids"],
                       "attention_mask": enc["attention_mask"],
                       "labels": etichette})
    if scartate:
        print(f"  {scartate} righe senza entita' escluse dal training")

    class Dataset(torch.utils.data.Dataset):
        def __len__(self):
            return len(esempi)

        def __getitem__(self, i):
            return esempi[i]

    return Dataset()


def main():
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
    ap.add_argument("--lr", type=float, default=LR)
    ap.add_argument("--max-len", type=int, default=MAX_LEN)
    args = ap.parse_args()

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
    print(f"  GPU: {torch.cuda.is_available()}")

    rows = load(args.train)
    print(f"{len(rows)} righe da {args.train}")
    if args.rehearsal:
        import random
        ripasso = load(args.rehearsal)
        quante = min(len(ripasso), int(len(rows) * args.rehearsal_ratio))
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
    ds = build_dataset(rows, tokenizer, label2id, TAG_MAP, DROP_TYPES)
    print(f"  {len(ds)} esempi di addestramento")

    out = Path(args.out)
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(out / "_run"),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch,
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
    (out / "finetune.json").write_text(json.dumps({
        "base": args.base, "train_file": args.train, "rows": len(rows),
        "examples": len(ds), "epochs": args.epochs, "batch": args.batch,
        "lr": args.lr, "max_len": args.max_len,
    }, indent=2), "utf-8")
    print(f"\nsalvato -> {out}")
    print("\nORA IL CONTROLLO CHE NON VA SALTATO:")
    print("  1) rimisura sul genere sicurezza (deve salire)")
    print("  2) rimisura sulla validation legale (NON deve scendere)")
    print("  Se il legale scende, non hai aggiunto una capacita': ne hai barattata una.")


if __name__ == "__main__":
    main()
