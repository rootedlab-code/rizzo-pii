# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec per l'app desktop CPU. Build: pyinstaller build.spec --noconfirm
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
# raccoglie codice + dati delle librerie con import dinamici
for pkg in ("transformers", "tokenizers", "safetensors", "huggingface_hub", "regex"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# Il modello impacchettato. Destinazione dentro l'exe: "pii_model", che app.py risolve
# via _resource_path. Sorgente in UN SOLO POSTO, condiviso con build_sidecar.spec e con
# i due script di build: erano quattro path scritti a mano, tenuti allineati da un
# commento, e infatti puntavano tutti a una directory che non esiste piu'.
# Override: PII_BUILD_MODEL=models/altro-checkpoint pyinstaller build.spec
import os
import sys
from pathlib import Path

MODEL = os.environ.get("PII_BUILD_MODEL", "models/rizzo-pii-0.3B-security")
if not (Path(MODEL) / "config.json").is_file():
    raise SystemExit(f"ERRORE: {MODEL} non e' un checkpoint (manca config.json). "
                     f"Scaricalo o indica PII_BUILD_MODEL.")
datas += [(MODEL, "pii_model")]

# Il timbro: dentro il pacchetto la directory si chiama "pii_model" per tutti, quindi
# il nome vero va congelato QUI, mentre si sa ancora quale checkpoint si sta copiando.
sys.path.insert(0, "src/app")
import model_info  # noqa: E402

Path("build").mkdir(exist_ok=True)
_stamp = Path("build") / model_info.STAMP_NAME
print(f"[build] timbro: {model_info.write_stamp(MODEL, _stamp, name=Path(MODEL).name)}")
datas += [(str(_stamp), "pii_model")]
datas += [("src/app/assets", "assets")]   # mascotte/icone -> app.py le serve da _resource_path("assets")
hiddenimports += ["fitz", "flask", "sklearn.utils._typedefs"]

# escludi tutto cio' che non serve (riduce dimensione e rumore)
excludes = [
    "tensorflow", "tensorflow_intel", "tf_keras", "keras", "jax", "jaxlib", "flax",
    "vllm", "FlagEmbedding", "flagembedding", "torchvision", "torchaudio",
    "matplotlib", "pandas", "scipy", "IPython", "notebook", "PyQt5", "PySide2",
]

a = Analysis(
    ["src/app/desktop_app.py"],
    pathex=["src/app"],          # cosi' PyInstaller trova il modulo 'app' importato da desktop_app
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AnonimizzatorePII",
    console=True,            # True per vedere i log; metti False per nasconderli
    disable_windowed_traceback=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="AnonimizzatorePII",
)
