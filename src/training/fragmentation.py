# -*- coding: utf-8 -*-
"""
Frammentazione: quanto spesso il sistema spezza un'entita' in piu' span adiacenti.

Nasce da un numero pubblicato che nessuno poteva ricalcolare. La scheda del modello
affermava «spezza FULLNAME nel 9,9% dei casi contro lo 0,3% del checkpoint di
partenza»: misura vera ma prodotta a mano, una volta sola, e per giunta sul testo
rotto da `from_bio()` (GEMELLI #23). Un numero pubblico che non ha un comando che lo
riproduce e' un numero di cui nessuno — nemmeno chi l'ha scritto — puo' rispondere.

DUE misure distinte, perche' rispondono a due domande diverse e confonderle e' facile:

  frammentazione = quota delle entita' FINALI che il sistema aveva prodotto spezzate.
                   «quanto spesso un nome esce a pezzi» — e' la claim della scheda.
  assorbiti      = quota degli span EMESSI che la fusione riassorbe.
                   «quanto lavoro fa la fusione» — cresce con la lunghezza media
                   delle entita', e su un corpus con molti nomi lunghi e' molto piu'
                   alta della prima a parita' di difetto.

Il sistema misurato e' quello che gira davvero: modello + rete regex/checksum +
`_merge()` dell'app, con i pacchetti di detector richiesti. Misurare il solo modello
direbbe quanto e' bravo il modello, che non e' il prodotto.

**Non si reimplementa la fusione.** `pre` e `post` si ottengono chiamando DUE VOLTE
lo stesso `_merge()` dell'app, la seconda con `_fuse_adjacent` neutralizzato. Scrivere
qui una seconda copia della semantica e' esattamente il difetto che questo repo
chiama "gemello": due implementazioni della stessa operazione che divergono, e la
misura che risponde al posto del prodotto.

    python src/training/fragmentation.py dataset/validation/test_riserva_legale.jsonl \
        --pred /tmp/pred_riserva_base.jsonl --labels FULLNAME

    python -m unittest discover -s tests
"""

import argparse
import collections
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "training"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import evaluate_entities as ev     # noqa: E402


def _candidates(text, model_entities, packs):
    """I candidati di `combined_entities()`: modello (mai validato) + rete regex.

    L'ordinamento totale non e' cosmetico: `model_entities` e' un set, e senza chiave
    completa i pari merito si risolvono in modo diverso a ogni processo (Python
    randomizza l'hash delle stringhe). E' lo stesso motivo per cui `normalize_entities`
    ordina per (start, end, label)."""
    cands = [{"start": e.start, "end": e.end, "label": e.label,
              "score": 1.0, "source": "modello", "validated": False}
             for e in sorted(model_entities, key=lambda x: (x.start, x.end, x.label))]
    cands += ev._regex_candidates(text, packs)
    return cands


def spans_pre_post(text, model_entities, packs=("cyber",)):
    """(span prima della fusione, entita' dopo la fusione).

    `_merge()` risolve le sovrapposizioni e POI fonde: per avere lo stato intermedio
    lo si chiama due volte, neutralizzando `_fuse_adjacent` nella prima. I candidati
    si copiano a ogni giro perche' `_merge()` li modifica sul posto (rifila gli spazi
    inglobati aggiustando start/end)."""
    app = ev._load_app()
    cands = _candidates(text, model_entities, packs)
    originale = app._fuse_adjacent
    try:
        app._fuse_adjacent = lambda kept, _text: kept
        pre = app._merge([dict(c) for c in cands], text)
    finally:
        app._fuse_adjacent = originale
    post = app._merge([dict(c) for c in cands], text)
    return pre, post


def tally(pre, post, stat=None):
    """Conteggi per tag: span emessi, entita' finali, entita' che erano spezzate.

    Un'entita' finale e' "spezzata" se contiene due o piu' span emessi dello stesso
    tag. La fusione estende solo `end`, e gli span di `pre` non si sovrappongono
    (`_merge` li ha gia' risolti), quindi il contenimento e' un test esatto, non
    un'euristica."""
    if stat is None:
        stat = collections.defaultdict(lambda: {"emessi": 0, "finali": 0, "spezzate": 0})
    for s in pre:
        stat[s["label"]]["emessi"] += 1
    for e in post:
        voce = stat[e["label"]]
        voce["finali"] += 1
        pezzi = sum(1 for s in pre
                    if s["label"] == e["label"]
                    and s["start"] >= e["start"] and s["end"] <= e["end"])
        if pezzi >= 2:
            voce["spezzate"] += 1
    return stat


def measure(gold_rows, pred_rows, packs=("cyber",), labels=None):
    """Percorre le righe appaiate e accumula i conteggi.

    Il controllo sui testi e' la guardia che sarebbe servita in GEMELLI #23: se le
    predizioni sono state prodotte da una ricostruzione diversa da quella del gold,
    gli offset non parlano della stessa frase e ogni numero a valle e' privo di senso.
    Meglio fermarsi che stampare una tabella dall'aria sana."""
    if len(gold_rows) != len(pred_rows):
        raise SystemExit(f"righe diverse: gold {len(gold_rows)}, pred {len(pred_rows)}")
    stat = collections.defaultdict(lambda: {"emessi": 0, "finali": 0, "spezzate": 0})
    for i, (gold, pred) in enumerate(zip(gold_rows, pred_rows)):
        if gold["source_text"] != pred["source_text"]:
            raise SystemExit(
                f"riga {i}: il testo del gold e quello delle predizioni non coincidono.\n"
                f"  gold: {gold['source_text'][:70]!r}\n"
                f"  pred: {pred['source_text'][:70]!r}\n"
                "Le predizioni vengono da un'altra ricostruzione: rigenerarle.")
        pre, post = spans_pre_post(gold["source_text"],
                                   ev.entities_of(pred), packs)
        if labels:
            pre = [s for s in pre if s["label"] in labels]
            post = [e for e in post if e["label"] in labels]
        tally(pre, post, stat)
    return stat


def report(stat, title, labels=None):
    """Tabella per tag. Un tag richiesto ma senza entita' dice N/V, non 0,0%.

    Un controllo che non ha potuto misurare nulla non e' un risultato buono: e' un
    risultato assente. E' la stessa distinzione del preflight."""
    print(f"\n{title}")
    print(f"  {'tag':<16}{'emessi':>8}{'finali':>8}{'spezzate':>10}"
          f"{'frammentaz.':>13}{'assorbiti':>11}")
    totale = {"emessi": 0, "finali": 0, "spezzate": 0}
    for label in sorted(labels or stat, key=lambda k: -stat[k]["finali"]):
        voce = stat.get(label, {"emessi": 0, "finali": 0, "spezzate": 0})
        for chiave in totale:
            totale[chiave] += voce[chiave]
        print(f"  {label:<16}{voce['emessi']:>8}{voce['finali']:>8}"
              f"{voce['spezzate']:>10}{_quota(voce['spezzate'], voce['finali']):>13}"
              f"{_quota(voce['emessi'] - voce['finali'], voce['emessi']):>11}")
    print(f"  {'MICRO':<16}{totale['emessi']:>8}{totale['finali']:>8}"
          f"{totale['spezzate']:>10}"
          f"{_quota(totale['spezzate'], totale['finali']):>13}"
          f"{_quota(totale['emessi'] - totale['finali'], totale['emessi']):>11}")
    return totale


def _quota(parte, intero):
    return f"{100.0 * parte / intero:.1f}%" if intero else "N/V"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("gold", help="file .jsonl del gold (serve per il testo, non per le etichette)")
    ap.add_argument("--pred", required=True, help="predizioni di UN modello su quel gold")
    ap.add_argument("--labels", default=None, help="tag da riportare, separati da virgola")
    ap.add_argument("--packs", default="", help="pacchetti di detector, es. cyber")
    ap.add_argument("--limit", type=int, default=None, help="usa solo le prime N righe")
    ap.add_argument("--title", default=None, help="intestazione della tabella")
    args = ap.parse_args()

    labels = [l.strip() for l in args.labels.split(",")] if args.labels else None
    packs = tuple(p for p in args.packs.split(",") if p)
    gold_rows = ev.load(args.gold)[:args.limit]
    pred_rows = ev.load(args.pred)[:args.limit]
    stat = measure(gold_rows, pred_rows, packs, labels)
    report(stat, args.title or f"{args.pred}  ({len(gold_rows)} righe)", labels)


if __name__ == "__main__":
    main()
