# -*- coding: utf-8 -*-
"""
Il timbro del checkpoint: quale modello sta girando davvero.

Serve a chiudere una domanda che dall'app in esecuzione era **impossibile**: con due
checkpoint da 1,2 GB e lo stesso `id2label` a 44 etichette, dentro un pacchetto
`MODEL_DIR` e' sempre `.../pii_model` e nessuna informazione distingue quello di
partenza da quello addestrato sul genere sicurezza. Due artefatti indistinguibili con
comportamenti diversi sono la forma di difetto che questo repo chiama gemello: cio' che
un artefatto e' contro cio' che dichiara di essere.

Il timbro si calcola **al build** (`model_info.json` accanto ai pesi) e si legge
all'avvio. Non si ricalcola a runtime: l'impronta di 1,2 GB sono secondi di I/O a ogni
partenza, per un dato che non cambia mai fra due avvii dello stesso pacchetto.

Modulo puro (solo stdlib) -> testabile senza torch e importabile da uno spec PyInstaller.
"""

import hashlib
import json
from pathlib import Path

STAMP_NAME = "model_info.json"
WEIGHTS_NAME = "model.safetensors"

# 1 MiB: leggere 1,2 GB in un colpo solo per farne l'impronta significa tenerli in RAM
# su una macchina che sta gia' impacchettando un modello.
_CHUNK = 1024 * 1024


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for blocco in iter(lambda: f.read(_CHUNK), b""):
            h.update(blocco)
    return h.hexdigest()


def build_stamp(model_dir, name=None) -> dict:
    """Il timbro di un checkpoint sul disco: nome, impronta dei pesi, numero di etichette.

    `name` di default e' il nome della directory, che nel repo coincide con l'id del
    modello su Hugging Face (`rizzo-pii-0.3B-security`). Nel pacchetto la directory si
    chiama `pii_model` per tutti, ed e' esattamente il motivo per cui il nome va
    congelato qui, al build, invece di essere dedotto dopo.

    Niente data di creazione: renderebbe due build dello stesso modello diverse fra
    loro, e l'impronta esiste proprio per poterle confrontare.
    """
    model_dir = Path(model_dir)
    cfg = json.loads((model_dir / "config.json").read_text("utf-8"))
    pesi = model_dir / WEIGHTS_NAME
    return {
        "name": name or model_dir.name,
        "labels": len(cfg.get("id2label") or {}),
        "sha256": _sha256(pesi) if pesi.is_file() else None,
    }


def write_stamp(model_dir, out_path, name=None) -> dict:
    """Calcola il timbro e lo scrive. Ritorna cio' che ha scritto."""
    timbro = build_stamp(model_dir, name=name)
    Path(out_path).write_text(json.dumps(timbro, indent=2), "utf-8")
    return timbro


def read_stamp(model_dir):
    """Il timbro accanto ai pesi, o None se il pacchetto e' precedente al timbro.

    None non e' un errore: e' 'non identificato'. Un pacchetto costruito prima che
    questo esistesse continua a funzionare, e l'interfaccia lo dichiara invece di
    inventare un nome."""
    p = Path(model_dir) / STAMP_NAME
    if not p.is_file():
        return None
    try:
        dati = json.loads(p.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return dati if isinstance(dati, dict) else None
