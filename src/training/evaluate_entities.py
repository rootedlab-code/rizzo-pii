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


# Rimappatura del training (train_pii.py: TAG_MAP e DROP_TYPES), applicata AL
# CARICAMENTO ai dati grezzi. Va applicata anche qui, altrimenti si confronta un gold
# con GIVENNAME+SURNAME contro un modello che produce FULLNAME e i nomi segnano
# recall 0 — un numero falso che sembrerebbe una scoperta.
#
# E' una copia, e le copie divergono: c'e' un test che rilegge train_pii.py e
# verifica che questa sia identica alla sua.
TAG_MAP = {
    "GIVENNAME": "FULLNAME", "SURNAME": "FULLNAME",
    "GIUDICE": "FULLNAME", "AVVOCATO": "FULLNAME", "CONVENUTO": "FULLNAME",
    "ATTORE": "FULLNAME", "TESTIMONE": "FULLNAME",
    "SEX": "GENDER", "TAXNUM": "PIVA", "PEC": "EMAIL", "RG": "DOCID",
    "IDCARDNUM": "ID_DOC", "PASSPORTNUM": "ID_DOC",
    "DRIVERLICENSENUM": "ID_DOC", "SOCIALNUM": "ID_DOC", "CONTO": "IBAN",
}
DROP_TYPES = {"TITLE", "TRIBUNAL"}


def normalize_entities(entities, text, apply_map=True):
    """Rimappa i tipi e FONDE le entita' adiacenti dello stesso tipo.

    La fusione e' la parte che conta: 'Mario' (GIVENNAME) e 'Rossi' (SURNAME) sono due
    entita' separate nel dato grezzo, con uno spazio non etichettato in mezzo, e il
    modello ne produce una sola — 'Mario Rossi' (FULLNAME). Senza fondere, lo span non
    coincide e l'entita' risulta mancata."""
    # Ordinamento TOTALE, non solo per start: gli Entity arrivano da un set, e
    # l'ordine di iterazione di un set di namedtuple con dentro una stringa dipende
    # dall'hash, che Python randomizza a ogni processo. Con la chiave parziale i pari
    # merito si risolvevano in modo diverso a ogni esecuzione e la stessa misura dava
    # 0.817, 0.819, 0.822 sullo stesso identico file.
    out = []
    for e in sorted(entities, key=lambda x: (x.start, x.end, x.label)):
        label = TAG_MAP.get(e.label, e.label) if apply_map else e.label
        if label in DROP_TYPES:
            continue
        if out and out[-1].label == label and not text[out[-1].end:e.start].strip():
            out[-1] = Entity(out[-1].start, e.end, label)
        else:
            out.append(Entity(e.start, e.end, label))
    return set(out)


def entities_of(rec, normalize=False):
    ents = {Entity(e["start"], e["end"], e["label"]) for e in rec["entities"]}
    return normalize_entities(ents, rec["source_text"]) if normalize else ents


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


def _regex_candidates(text, packs=()):
    """Candidati della rete regex ATTIVA dell'app: core piu' i pacchetti richiesti.

    Usare i soli detector cyber sarebbe sbagliato su documenti legali: CF, IBAN, PIVA
    e carta di credito li risolve la rete CORE con i checksum, ed e' li' che il
    prodotto ripone la fiducia — il modello quegli identificatori li FRAMMENTA
    ('RCCMRT60T58H703I' esce come CF+CF+ID_DOC+ID_DOC+CF). Misurare il modello da solo
    su quei tag misura qualcosa che in produzione non decide niente."""
    app = _load_app()
    app.enable_packs(list(packs))
    cands = []
    for label, rx, validator, _strict in app.ACTIVE_DETECTORS:
        for m in rx.finditer(text):
            ok = validator is None or validator(m.group())
            if ok or not _strict:
                cands.append({"start": m.start(), "end": m.end(), "label": label,
                              "score": 1.0, "source": "regex", "validated": bool(ok)})
    return cands


def detector_entities(text, labels=None, merge=True, packs=("cyber",)):
    """Entita' secondo la rete regex+validatori. E' il campione da battere.

    merge=True applica la stessa risoluzione delle sovrapposizioni dell'app, che e'
    cio' che conta: il numero utile e' quanto sbaglia il SISTEMA, non quanto si
    accavallano i suoi pezzi."""
    cands = _regex_candidates(text, packs)
    if merge:
        cands = _load_app()._merge(cands, text)
    return {Entity(c["start"], c["end"], c["label"]) for c in cands
            if not labels or c["label"] in labels}


def combined_entities(text, model_entities, labels=None, packs=("cyber",)):
    """Modello + rete regex, fusi come fa analyze(): e' cio' che gira davvero.

    Misurare il solo modello dice quanto e' bravo il modello; misurare le sole regex
    dice quanto sono brave le regex. Nessuno dei due e' il prodotto. E la differenza
    non e' piccola: a pari span vince quello validato, quindi una data riconosciuta
    dalla regex sostituisce lo span troncato del modello invece di affiancarlo."""
    cands = [{"start": e.start, "end": e.end, "label": e.label,
              "score": 1.0, "source": "modello", "validated": False}
             for e in sorted(model_entities, key=lambda x: (x.start, x.end, x.label))]
    cands += _regex_candidates(text, packs)
    merged = _load_app()._merge(cands, text)
    return {Entity(c["start"], c["end"], c["label"]) for c in merged
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


def from_bio(rec):
    """Converte una riga {tokens, bio_labels} nel formato {source_text, entities}.

    Serve per la validation legale del progetto, che e' distribuita per token: senza
    conversione non si potrebbe misurare la REGRESSIONE, cioe' se addestrando sul
    genere sicurezza il modello peggiora sul caso d'uso originale. E' il controllo che
    si salta sempre, perche' richiede di misurare qualcosa che non si sta cercando di
    migliorare.

    I token della validation sono **WordPiece**, e i pezzi di continuazione portano il
    prefisso `##`. Unendoli tutti con uno spazio si otteneva `CA ##P` al posto di
    `CAP` e `Son ##ce ##bo ##z` al posto di un nome: misurato, il **63,7%** delle
    righe conteneva marcatori `##` e il **45,8%** delle entita' del gold ne aveva uno
    dentro il proprio span.

    Il confronto A/B restava valido — gold e predizione partono dallo stesso testo —
    ma tutto il resto no: i valori assoluti descrivevano un testo che in produzione
    non esiste, la rete regex girava su identificatori spezzati, e i quattro tag
    dichiarati "deboli" (`CREDITCARDNUMBER`, `IBAN`, `AMOUNT`, `ZIPCODE`) sono
    esattamente gli alfanumerici lunghi che WordPiece divide.

    Qui `##x` si attacca al token precedente senza spazio, come vuole la convenzione.
    La spaziatura resta approssimata — non si recupera dai soli token — ma le parole
    tornano intere."""
    parts, entities, pos = [], [], 0
    corrente = None
    for token, label in zip(rec["tokens"], rec["bio_labels"]):
        continua = token.startswith("##") and len(token) > 2 and parts
        pezzo = token[2:] if continua else token
        if parts and not continua:
            parts.append(" ")
            pos += 1
        start = pos
        parts.append(pezzo)
        pos += len(pezzo)
        end = pos
        tipo = label.split("-", 1)[1] if label != "O" and "-" in label else None
        if tipo and label.startswith("I-") and corrente and corrente["label"] == tipo:
            corrente["end"] = end
            continue
        if corrente:
            entities.append(corrente)
            corrente = None
        if tipo:
            corrente = {"start": start, "end": end, "label": tipo}
    if corrente:
        entities.append(corrente)
    text = "".join(parts)
    for e in entities:
        e["value"] = text[e["start"]:e["end"]]
    return {"source_text": text, "entities": entities,
            "tokens": rec["tokens"], "bio_labels": rec["bio_labels"]}


def load(path):
    """Legge un .jsonl del progetto, in entrambi i formati in circolazione."""
    out = []
    for line in Path(path).open(encoding="utf-8"):
        rec = json.loads(line)
        out.append(rec if "source_text" in rec else from_bio(rec))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("gold", help="file .jsonl con le entita' vere")
    ap.add_argument("--pred", default=None,
                    help="file .jsonl con le stesse righe e le entita' predette; "
                         "senza questo si valuta la rete regex")
    ap.add_argument("--labels", default=None,
                    help="limita ai soli tag indicati, es. \"IP,DOMAIN,HASH\"")
    ap.add_argument("--limit", type=int, default=None,
                    help="usa solo le prime N righe del gold. Deve coincidere con il "
                         "--limit usato in predizione: due campioni diversi non si "
                         "confrontano, e il controllo di regressione perderebbe senso")
    ap.add_argument("--packs", default="cyber",
                    help="pacchetti di detector attivi, es. \"cyber\" oppure \"\" per il "
                         "solo core. Sui documenti legali il core basta ed e' corretto")
    ap.add_argument("--with-detectors", action="store_true",
                    help="fonde le predizioni con la rete regex, come fa analyze(): "
                         "e' la misura del PRODOTTO, non di una sua meta'")
    ap.add_argument("--normalize", action="store_true",
                    help="applica TAG_MAP e fonde le entita' adiacenti, come fa il "
                         "training al caricamento. SERVE per confrontarsi con un "
                         "modello addestrato: senza, GIVENNAME+SURNAME nel gold non "
                         "coincidono col FULLNAME che il modello produce")
    args = ap.parse_args()

    labels = {t.strip().upper() for t in args.labels.split(",")} if args.labels else None
    packs = tuple(p.strip() for p in args.packs.split(",") if p.strip())
    gold_rows = load(args.gold)
    if args.limit:
        gold_rows = gold_rows[:args.limit]
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
        if args.with_detectors:
            pairs = [(keep(entities_of(g, args.normalize)),
                      keep(combined_entities(g["source_text"],
                                             entities_of(p, args.normalize),
                                             labels, packs)))
                     for g, p in zip(gold_rows, pred_rows)]
            titolo = f"Modello ({args.pred}) + rete regex, fusi come nell'app"
        else:
            pairs = [(keep(entities_of(g, args.normalize)),
                      keep(entities_of(p, args.normalize)))
                     for g, p in zip(gold_rows, pred_rows)]
            titolo = f"Solo modello, da {args.pred}"
        report(score(pairs), titolo)
    else:
        pairs = [(keep(entities_of(g, args.normalize)),
                  keep(detector_entities(g["source_text"], labels, packs=packs)))
                 for g in gold_rows]
        r, _p, _f = report(score(pairs), "Rete regex+validatori (campione da battere)")
        print(f"\n  Un modello addestrato sui tag cyber deve superare recall {r:.3f}")
        print("  per giustificare il riaddestramento: sotto quella soglia la regex,")
        print("  che e' esatta e non ha bisogno di GPU, resta la scelta migliore.")


if __name__ == "__main__":
    main()
