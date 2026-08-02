#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Valutazione entity-level su un file .jsonl del progetto, e confronto con la rete
regex.

Serve a rispondere alla sola domanda che conta prima di riaddestrare: **il modello
sarebbe piu' affidabile di quello che gia' abbiamo?** Per i tag cyber il campione da
battere non e' un altro modello, sono i detector deterministici: se una regex con
validatore fa meglio, il riaddestramento non vale il suo costo.

Perche' entity-level e non token-level. Un'entita' vale se lo span e' esatto: un
`FULLNAME` di cui si prende solo il nome e non il cognome lascia il cognome in
chiaro, quindi conta come mancato, non come mezzo successo. La metrica per token
lo darebbe per meta' giusto e mentirebbe proprio sul caso che ci interessa.

Perche' la RECALL conta piu' della precision. Un'entita' mancata e' un dato
sensibile in chiaro; un falso positivo e' una parola illeggibile. Non sono errori
simmetrici, quindi l'F1 — che li pesa uguali — non e' il numero da guardare per
primo. Nella tabella la recall viene prima, ed e' quella su cui decidere.

    # campione da battere: i detector sul file di valutazione
    python src/training/evaluate_entities.py dataset/synthetic/..._eval.jsonl

    # confronto fra due sistemi (gold = file, pred = altro file con gli stessi testi)
    python src/training/evaluate_entities.py gold.jsonl --pred pred.jsonl
"""

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "app"))

import detectors_cyber  # noqa: E402

# Un'entita' e' identificata da dove sta e da cosa e': confrontare i VALORI invece
# degli offset farebbe passare per corretta un'entita' trovata nel punto sbagliato.
Entity = collections.namedtuple("Entity", "start end label")


def entities_of(rec):
    return {Entity(e["start"], e["end"], e["label"]) for e in rec["entities"]}


def _load_app():
    """Importa app.py col modello sostituito da uno stub.

    Serve per riusare il SUO _merge(): senza, si misurano i detector grezzi invece
    del sistema come gira davvero. La differenza non e' teorica — un dominio dentro
    una URL fa scattare due detector, e senza merge il dominio annidato viene contato
    come falso positivo mentre nell'app l'URL vince e il dominio sparisce."""
    import types
    torch = types.ModuleType("torch")
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    sys.modules.setdefault("torch", torch)
    transformers = types.ModuleType("transformers")
    transformers.pipeline = lambda *a, **k: types.SimpleNamespace(
        model=types.SimpleNamespace(config=types.SimpleNamespace(label2id={})),
        __call__=lambda *_a, **_k: [])
    sys.modules.setdefault("transformers", transformers)
    fitz = types.ModuleType("fitz")
    fitz.open = lambda *a, **k: None
    sys.modules.setdefault("fitz", fitz)
    import app
    return app


def detector_entities(text, labels=None, merge=True):
    """Entita' secondo la rete regex+validatori. E' il campione da battere.

    merge=True applica la stessa risoluzione delle sovrapposizioni dell'app, che e'
    cio' che conta: il numero utile e' quanto sbaglia il SISTEMA, non quanto si
    accavallano i suoi pezzi."""
    cands = []
    for label, rx, validator, _strict in detectors_cyber.DETECTORS:
        for m in rx.finditer(text):
            ok = validator is None or validator(m.group())
            if ok:
                cands.append({"start": m.start(), "end": m.end(), "label": label,
                              "score": 1.0, "source": "regex", "validated": ok})
    if merge:
        cands = _load_app()._merge(cands, text)
    return {Entity(c["start"], c["end"], c["label"]) for c in cands
            if not labels or c["label"] in labels}


def score(pairs):
    """(gold, pred) per riga -> statistiche per label e micro-media.

    tp/fp/fn si contano per label; la micro-media somma i conteggi invece di mediare
    gli F1, cosi' un tag raro non pesa quanto uno frequente solo perche' esiste."""
    stat = collections.defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for gold, pred in pairs:
        for e in pred - gold:
            stat[e.label]["fp"] += 1
        for e in gold - pred:
            stat[e.label]["fn"] += 1
        for e in gold & pred:
            stat[e.label]["tp"] += 1
    return stat


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def report(stat, title):
    """Tabella per tag, recall per prima. Ritorna la micro-media."""
    print(f"\n{title}")
    print(f"  {'tag':<14}{'recall':>8}{'prec':>8}{'F1':>8}{'gold':>8}{'mancati':>9}{'falsi+':>8}")
    tot = {"tp": 0, "fp": 0, "fn": 0}
    for label in sorted(stat, key=lambda k: -(stat[k]["tp"] + stat[k]["fn"])):
        s = stat[label]
        p, r, f = prf(s["tp"], s["fp"], s["fn"])
        for k in tot:
            tot[k] += s[k]
        print(f"  {label:<14}{r:>8.3f}{p:>8.3f}{f:>8.3f}"
              f"{s['tp'] + s['fn']:>8}{s['fn']:>9}{s['fp']:>8}")
    p, r, f = prf(tot["tp"], tot["fp"], tot["fn"])
    print(f"  {'MICRO':<14}{r:>8.3f}{p:>8.3f}{f:>8.3f}"
          f"{tot['tp'] + tot['fn']:>8}{tot['fn']:>9}{tot['fp']:>8}")
    return r, p, f


def load(path):
    return [json.loads(line) for line in Path(path).open(encoding="utf-8")]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("gold", help="file .jsonl con le entita' vere")
    ap.add_argument("--pred", default=None,
                    help="file .jsonl con le stesse righe e le entita' predette; "
                         "senza questo si valuta la rete regex")
    ap.add_argument("--labels", default=None,
                    help="limita ai soli tag indicati, es. \"IP,DOMAIN,HASH\"")
    args = ap.parse_args()

    labels = {t.strip().upper() for t in args.labels.split(",")} if args.labels else None
    gold_rows = load(args.gold)
    print(f"{len(gold_rows)} righe da {args.gold}")

    def keep(entities):
        return {e for e in entities if not labels or e.label in labels}

    if args.pred:
        pred_rows = load(args.pred)
        if len(pred_rows) != len(gold_rows):
            sys.exit(f"ERRORE: {len(pred_rows)} righe predette contro {len(gold_rows)} vere")
        for g, p in zip(gold_rows, pred_rows):
            if g["source_text"] != p["source_text"]:
                sys.exit("ERRORE: i due file non contengono gli stessi testi")
        pairs = [(keep(entities_of(g)), keep(entities_of(p)))
                 for g, p in zip(gold_rows, pred_rows)]
        report(score(pairs), f"Predizioni da {args.pred}")
    else:
        pairs = [(keep(entities_of(g)),
                  keep(detector_entities(g["source_text"], labels)))
                 for g in gold_rows]
        r, _p, _f = report(score(pairs), "Rete regex+validatori (campione da battere)")
        print(f"\n  Un modello addestrato sui tag cyber deve superare recall {r:.3f}")
        print("  per giustificare il riaddestramento: sotto quella soglia la regex,")
        print("  che e' esatta e non ha bisogno di GPU, resta la scelta migliore.")


if __name__ == "__main__":
    main()
