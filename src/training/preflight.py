#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Preflight — gira in secondi, prima di ogni corsa che costa.

Verifica le coppie che devono coincidere (vedi docs/GEMELLI.md) e fallisce
rumorosamente. Un controllo che non ha potuto verificare nulla lo DICE: se confronta
un elenco di pacchetti e nessuno e' installato, l'esito e' "non verificato", non
"OK" — altrimenti il preflight diventa il difetto che dovrebbe prevenire.

    python src/training/preflight.py --train ... --eval ... [--manifest file.json]

Alla prima esecuzione scrive il manifesto; alle successive lo confronta.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "training"))
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))
sys.path.insert(0, str(ROOT / "src" / "app"))

ESITI = []


def check(nome, ok, dettaglio="", verificabile=True):
    stato = "OK  " if ok else "FALLITO"
    if not verificabile:
        stato = "N/V "          # non verificato: non e' un OK
    ESITI.append((nome, stato, dettaglio))
    return ok


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blocco in iter(lambda: f.read(1 << 20), b""):
            h.update(blocco)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--train", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--rehearsal", default=None)
    ap.add_argument("--manifest", default="dataset/manifesto.json")
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--base", default="rizzoaiacademy/rizzo-pii-0.3B")
    args = ap.parse_args()

    # --- 1. impronte del corpus -------------------------------------------- #
    file = {"train": args.train, "eval": args.eval}
    if args.rehearsal:
        file["rehearsal"] = args.rehearsal
    mancanti = [k for k, v in file.items() if not Path(v).is_file()]
    if not check("i file esistono", not mancanti, ", ".join(mancanti)):
        stampa_e_esci()
    impronte = {k: sha(v) for k, v in file.items()}
    m = Path(args.manifest)
    if m.is_file():
        atteso = json.loads(m.read_text())
        diverse = [k for k in impronte if atteso.get(k) != impronte[k]]
        check("impronte contro il manifesto", not diverse,
              f"cambiati: {', '.join(diverse)}" if diverse else "invariate")
    else:
        m.parent.mkdir(parents=True, exist_ok=True)
        m.write_text(json.dumps(impronte, indent=2))
        check("manifesto", True, f"scritto per la prima volta in {m}", verificabile=False)

    # --- 2. nessuna sovrapposizione fra train ed eval ----------------------- #
    import generate_cyber_pii as cy
    import evaluate_entities as ev

    def scheletri(p):
        return {cy.skeleton(r) for r in ev.load(p)}

    tr, ev_ = scheletri(args.train), scheletri(args.eval)
    check("scheletri train/eval disgiunti", not (tr & ev_),
          f"condivisi: {len(tr & ev_)}")

    # --- 3. i gemelli delle costanti --------------------------------------- #
    import ast
    src = (ROOT / "src" / "training" / "train_pii.py").read_text(encoding="utf-8")
    trovate = {}
    for nodo in ast.parse(src).body:
        if isinstance(nodo, ast.Assign) and isinstance(nodo.targets[0], ast.Name) \
                and nodo.targets[0].id in ("TAG_MAP", "DROP_TYPES"):
            trovate[nodo.targets[0].id] = ast.literal_eval(nodo.value)
    check("TAG_MAP allineata col training",
          trovate.get("TAG_MAP") == ev.TAG_MAP and trovate.get("DROP_TYPES") == ev.DROP_TYPES)


    # --- 4. riproducibilita' della misura ----------------------------------- #
    e = {ev.Entity(0, 5, "GIVENNAME"), ev.Entity(6, 11, "SURNAME")}
    testo = "Mario Rossi ha firmato."
    check("normalizzazione deterministica",
          all(ev.normalize_entities(set(e), testo) ==
              ev.normalize_entities(set(reversed(sorted(e))), testo) for _ in range(20)))

    # --- 5. niente esempi oltre max_length ---------------------------------- #
    try:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained(args.base)
        righe = ev.load(args.train)[:500]
        lunghe = sum(1 for r in righe
                     if len(tok(r["tokens"], is_split_into_words=True)["input_ids"]) > args.max_len)
        check(f"esempi entro max_len={args.max_len}", lunghe == 0,
              f"{lunghe}/500 troncati" if lunghe else "campione di 500")
    except ImportError:
        check("esempi entro max_len", False, "transformers assente", verificabile=False)

    # --- 6. ambiente -------------------------------------------------------- #
    versioni = {}
    for mod in ("torch", "transformers", "accelerate"):
        try:
            versioni[mod] = __import__(mod).__version__
        except ImportError:
            versioni[mod] = None
    assenti = [k for k, v in versioni.items() if v is None]
    check("librerie di training presenti", not assenti,
          ", ".join(f"{k} {v}" for k, v in versioni.items() if v) +
          (f" | ASSENTI: {', '.join(assenti)}" if assenti else ""),
          verificabile=not assenti)
    try:
        import torch
        check("GPU disponibile", torch.cuda.is_available(),
              torch.cuda.get_device_name(0) if torch.cuda.is_available() else "solo CPU")
    except ImportError:
        check("GPU disponibile", False, "torch assente", verificabile=False)

    stampa_e_esci()


def stampa_e_esci():
    print("\nPREFLIGHT")
    larghezza = max(len(n) for n, _, _ in ESITI)
    for nome, stato, dettaglio in ESITI:
        print(f"  [{stato}] {nome:<{larghezza}}  {dettaglio}")
    falliti = [n for n, s, _ in ESITI if s.strip() == "FALLITO"]
    nonver = [n for n, s, _ in ESITI if s.strip() == "N/V"]
    if nonver:
        print(f"\n  NON VERIFICATI ({len(nonver)}): {', '.join(nonver)}")
        print("  Un controllo che non ha potuto verificare nulla non e' un OK.")
    if falliti:
        print(f"\n  FALLITI: {', '.join(falliti)}")
        sys.exit(1)
    print("\n  Nessun fallimento." + ("  Ma vedi i non verificati." if nonver else ""))
    sys.exit(0)


if __name__ == "__main__":
    main()
