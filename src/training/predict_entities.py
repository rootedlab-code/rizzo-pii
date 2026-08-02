#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fa predire le entita' a un modello di token classification su un file .jsonl del
progetto, e scrive un file nello stesso formato — pronto per evaluate_entities.py.

Serve a rispondere alla domanda che precede qualunque riaddestramento: **il modello
che gia' esiste quanto e' bravo sul genere che ci interessa?** Senza quel numero,
dopo l'addestramento non si potrebbe dire se e' migliorato.

    # scarica ed esegue il modello rilasciato sul file di valutazione
    python src/training/predict_entities.py eval.jsonl --out pred.jsonl

    # poi
    python src/training/evaluate_entities.py eval.jsonl --pred pred.jsonl

Il chunking ricalca quello dell'app (MAX_WORDS/OVERLAP con offset globali), perche'
misurare il modello in un modo e usarlo in un altro darebbe un numero che non
descrive il sistema che poi gira davvero.
"""

import argparse
import json
import sys
from pathlib import Path

DEFAULT_MODEL = "rizzoaiacademy/rizzo-pii-0.3B"
MAX_WORDS = 120       # come src/app/app.py
OVERLAP = 20


def chunks(text, max_words=MAX_WORDS, overlap=OVERLAP):
    """[(sottostringa, offset_globale)] senza tagliare parole — come fa l'app."""
    words, spans, pos = [], [], 0
    for w in text.split(" "):
        spans.append((pos, pos + len(w)))
        words.append(w)
        pos += len(w) + 1
    if not words:
        return []
    out, i = [], 0
    while i < len(words):
        j = min(i + max_words, len(words))
        start, end = spans[i][0], spans[j - 1][1]
        out.append((text[start:end], start))
        if j >= len(words):
            break
        i = j - overlap
    return out


def predict(model_name, rows, device="cpu", batch=16):
    """Entita' predette per ogni riga, con gli offset riferiti al testo intero."""
    from transformers import pipeline

    print(f"carico {model_name} su {device}...", flush=True)
    nlp = pipeline("token-classification", model=model_name, device=device,
                   aggregation_strategy="simple")
    print("modello pronto.", flush=True)

    out = []
    for k, rec in enumerate(rows, 1):
        text = rec["source_text"]
        found, seen = [], set()
        for piece, offset in chunks(text):
            for ent in nlp(piece):
                start, end = ent["start"] + offset, ent["end"] + offset
                # Gli offset del tokenizer INCLUDONO lo spazio che precede il token:
                # il modello restituisce ' Stefano Fabbri' invece di 'Stefano Fabbri',
                # e uno span lungo un carattere in piu' non coincide mai con quello
                # vero. Misurato prima della correzione: FULLNAME, CITY e ORG a recall
                # 0.000 con centinaia di falsi positivi — cioe' le entita' venivano
                # trovate e contate come sbagliate. Sopravvivevano solo EMAIL e
                # PROVINCE, precedute da '(' e quindi senza spazio da includere.
                while start < end and text[start].isspace():
                    start += 1
                while end > start and text[end - 1].isspace():
                    end -= 1
                if start >= end:
                    continue
                # il chunking si sovrappone: la stessa entita' esce due volte
                key = (start, end, ent["entity_group"])
                if key in seen:
                    continue
                seen.add(key)
                found.append({"start": start, "end": end,
                              "label": ent["entity_group"],
                              "value": text[start:end],
                              "score": float(ent["score"])})
        out.append({**rec, "entities": found})
        if k % 100 == 0:
            print(f"  {k}/{len(rows)}", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("gold", help="file .jsonl di partenza")
    ap.add_argument("--out", required=True, help="dove scrivere le predizioni")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--device", default="cpu", help="cpu oppure 0 per la prima GPU")
    ap.add_argument("--limit", type=int, default=None, help="usa solo le prime N righe")
    args = ap.parse_args()

    rows = [json.loads(line) for line in Path(args.gold).open(encoding="utf-8")]
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} righe da {args.gold}")

    device = args.device if args.device == "cpu" else int(args.device)
    preds = predict(args.model, rows, device=device)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in preds:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(out)
    tot = sum(len(r["entities"]) for r in preds)
    print(f"\n{tot} entita' predette -> {out}")


if __name__ == "__main__":
    main()
