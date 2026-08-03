#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Confronto APPAIATO fra due sistemi sulle stesse entita' del gold.

E' il test che docs/CRITERIO.md richiede per decidere se un modello addestrato puo'
sostituire quello in produzione, e non era eseguibile: il criterio era scritto, lo
strumento no.

Perche' appaiato e non due intervalli separati: i due sistemi sono misurati sulle
STESSE entita', quindi la maggior parte degli esiti coincide e non porta
informazione. Confrontare due intervalli di confidenza butta via l'appaiamento, e
con campioni realistici li fa sovrapporre quasi sempre — cioe' conclude
"indistinguibili" anche quando c'e' una differenza vera. Con una sola esecuzione
possibile per configurazione, McNemar e' l'unico test con un errore di tipo I
accettabile (Dietterich, Neural Computation 1998).

Si usa la forma ESATTA (binomiale a due code) e non l'approssimazione chi-quadro,
perche' con poche discordanze quest'ultima e' inaffidabile ed e' proprio il regime
in cui ci si trova quando due modelli si somigliano.

    python src/training/mcnemar.py dataset/validation/validation_real.jsonl \\
        --a pred_baseline.jsonl --b pred_addestrato.jsonl --limit 2000 --packs ""

Un p piccolo dice che i due sistemi DIFFERISCONO, non che il secondo sia migliore:
la direzione si legge nei due conteggi delle discordanze, che vengono stampati.
"""

import argparse
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "training"))


def mcnemar_exact(solo_a, solo_b):
    """p a due code del test esatto di McNemar sulle sole discordanze.

    Sotto l'ipotesi nulla ciascuna discordanza cade da una parte o dall'altra con
    probabilita' 1/2, quindi il conteggio minore segue una binomiale(n, 1/2) con
    n = solo_a + solo_b. Nessuna discordanza -> nessuna evidenza -> p = 1."""
    n = solo_a + solo_b
    if n == 0:
        return 1.0
    k = min(solo_a, solo_b)
    coda = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * coda)


def esiti_per_entita(gold_rows, pred_rows, labels=None, packs=(), normalize=True):
    """Per ogni entita' del gold, nell'ordine: il sistema l'ha trovata?

    L'ordine e' totale e deterministico (start, end, label) perche' due chiamate
    devono produrre liste allineabili elemento per elemento — e' l'appaiamento
    stesso, e un ordine che dipendesse dall'hash dei set lo romperebbe in
    silenzio."""
    import evaluate_entities as ev

    if len(pred_rows) != len(gold_rows):
        raise ValueError(f"{len(pred_rows)} righe predette contro {len(gold_rows)} vere")
    fuori = []
    for g, p in zip(gold_rows, pred_rows):
        if g["source_text"] != p["source_text"]:
            raise ValueError("i due file non contengono gli stessi testi")
        oro = ev.entities_of(g, normalize)
        sistema = ev.combined_entities(g["source_text"], ev.entities_of(p, normalize),
                                       labels, packs)
        if labels:
            oro = {e for e in oro if e.label in labels}
        for e in sorted(oro, key=lambda x: (x.start, x.end, x.label)):
            fuori.append((e.label, e in sistema))
    return fuori


def confronta(esiti_a, esiti_b):
    """(recuperate_a, recuperate_b, solo_a, solo_b, p) fra due liste appaiate."""
    if [lab for lab, _ in esiti_a] != [lab for lab, _ in esiti_b]:
        raise ValueError("le due liste non sono appaiate sulle stesse entita'")
    solo_a = sum(1 for (_, x), (_, y) in zip(esiti_a, esiti_b) if x and not y)
    solo_b = sum(1 for (_, x), (_, y) in zip(esiti_a, esiti_b) if y and not x)
    return (sum(v for _, v in esiti_a), sum(v for _, v in esiti_b),
            solo_a, solo_b, mcnemar_exact(solo_a, solo_b))


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("gold", help="file .jsonl con le entita' vere")
    ap.add_argument("--a", required=True, help="predizioni del sistema di riferimento")
    ap.add_argument("--b", required=True, help="predizioni del sistema candidato")
    ap.add_argument("--limit", type=int, default=None,
                    help="usa solo le prime N righe: DEVE essere lo stesso valore "
                         "usato per produrre entrambe le predizioni")
    ap.add_argument("--labels", default=None, help="solo questi tag, separati da virgola")
    ap.add_argument("--packs", default="",
                    help="pacchetti di detector da affiancare al modello; vuoto = "
                         "solo la rete core, com'e' in produzione sul dominio legale")
    ap.add_argument("--no-normalize", action="store_true",
                    help="non applicare TAG_MAP: senza, i tag fusi segnano recall 0")
    ap.add_argument("--alpha", type=float, default=0.05)
    return ap


def main():
    args = build_parser().parse_args()
    import evaluate_entities as ev

    labels = ({t.strip().upper() for t in args.labels.split(",")} if args.labels
              else None)
    packs = tuple(p.strip() for p in args.packs.split(",") if p.strip())
    gold = ev.load(args.gold)[:args.limit] if args.limit else ev.load(args.gold)
    normalize = not args.no_normalize

    def leggi(percorso):
        righe = ev.load(percorso)
        return esiti_per_entita(gold, righe[:len(gold)], labels, packs, normalize)

    try:
        a, b = leggi(args.a), leggi(args.b)
    except ValueError as errore:
        sys.exit(f"ERRORE: {errore}")

    rec_a, rec_b, solo_a, solo_b, p = confronta(a, b)
    print(f"\n{len(a)} entita' del gold, {len(gold)} righe, "
          f"detector: {', '.join(packs) or 'solo rete core'}")
    print(f"  A  {args.a}\n     {rec_a}/{len(a)} recuperate")
    print(f"  B  {args.b}\n     {rec_b}/{len(b)} recuperate")
    print(f"\n  discordanze: solo A = {solo_a}, solo B = {solo_b}")
    print(f"  McNemar esatto (due code): p = {p:.6f}")

    if p >= args.alpha:
        print(f"\n  INDISTINGUIBILI a alpha={args.alpha}. Non significa 'uguali':")
        print("  significa che questo campione non basta a separarli.")
        sys.exit(0)
    verso = "B recupera piu' di quanto perde" if solo_b > solo_a else \
            "B perde piu' di quanto recupera"
    print(f"\n  DIVERSI a alpha={args.alpha} — {verso}.")
    # CRITERIO.md regola A: servono ENTRAMBE le condizioni, p e direzione
    sys.exit(0 if solo_b > solo_a else 1)


if __name__ == "__main__":
    main()
