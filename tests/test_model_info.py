# -*- coding: utf-8 -*-
"""
Test del timbro del checkpoint (src/app/model_info.py).

Il difetto che il timbro chiude: due checkpoint da 1,2 GB con lo stesso id2label a 44
etichette, e dentro un pacchetto MODEL_DIR e' sempre .../pii_model. Da un'app in
esecuzione era impossibile sapere quale dei due stesse girando. Qui si prova che il
timbro li distingue, e che la sua assenza si dichiara invece di essere indovinata.

    python -m unittest discover -s tests
"""

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "app"))

sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_info as mi     # noqa: E402
import modello_finto        # noqa: E402


def _install_stubs():
    """Stessi stub del resto della suite: qui non interessa cosa il modello predice.

    Il finto viene da `modello_finto` e non da un `SimpleNamespace` con un attributo
    `__call__`: i metodi speciali Python li cerca sul TIPO, non sull'istanza, quindi
    quello non era chiamabile. Non si notava perche' questo file non chiama mai
    `analyze()` — ma lo stub e' installato con `setdefault`, quindi quando toccava a
    questo file arrivare per primo lo ereditavano tutti gli altri, e i 33 test che
    passano da `analyze()` morivano con 'SimpleNamespace object is not callable'."""
    torch = types.ModuleType("torch")
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    sys.modules.setdefault("torch", torch)
    transformers = types.ModuleType("transformers")
    transformers.pipeline = lambda *a, **k: modello_finto.ModelloFinto(
        [f"B-L{i}" for i in range(44)])
    sys.modules.setdefault("transformers", transformers)
    fitz = types.ModuleType("fitz")
    fitz.open = lambda *a, **k: None
    sys.modules.setdefault("fitz", fitz)


_install_stubs()

import app as _app     # noqa: E402


def _fai_checkpoint(base, nome, pesi=b"", etichette=44):
    d = Path(base) / nome
    d.mkdir(parents=True, exist_ok=True)
    id2label = {str(i): f"L{i}" for i in range(etichette)}
    (d / "config.json").write_text(json.dumps({"id2label": id2label}), "utf-8")
    (d / mi.WEIGHTS_NAME).write_bytes(pesi)
    return d


class TimbroTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class TestCostruzione(TimbroTestCase):

    def test_the_stamp_names_the_checkpoint_and_counts_its_labels(self):
        d = _fai_checkpoint(self.tmp, "rizzo-pii-0.3B-security", b"pesi")

        timbro = mi.build_stamp(d)

        self.assertEqual(timbro["name"], "rizzo-pii-0.3B-security")
        self.assertEqual(timbro["labels"], 44)
        self.assertTrue(timbro["sha256"])

    def test_two_checkpoints_with_the_same_labels_get_different_fingerprints(self):
        # e' IL caso reale: base e security hanno id2label identico, 44 etichette.
        # Se il timbro non li distinguesse non servirebbe a niente.
        a = _fai_checkpoint(self.tmp, "base", b"pesi-del-modello-A")
        b = _fai_checkpoint(self.tmp, "security", b"pesi-del-modello-B")

        self.assertEqual(mi.build_stamp(a)["labels"], mi.build_stamp(b)["labels"])
        self.assertNotEqual(mi.build_stamp(a)["sha256"], mi.build_stamp(b)["sha256"])

    def test_the_name_can_be_frozen_at_build_time(self):
        # nel pacchetto la directory si chiama pii_model per tutti: il nome vero va
        # congelato al build, quando ancora si sa quale checkpoint si sta copiando
        d = _fai_checkpoint(self.tmp, "pii_model", b"pesi")

        self.assertEqual(mi.build_stamp(d, name="rizzo-pii-0.3B-security")["name"],
                         "rizzo-pii-0.3B-security")

    def test_the_fingerprint_is_stable_across_two_runs(self):
        # senza questo il timbro non permetterebbe di confrontare due build dello
        # stesso modello, che e' la ragione per cui non contiene una data
        d = _fai_checkpoint(self.tmp, "m", b"x" * (1024 * 1024 + 7))

        self.assertEqual(mi.build_stamp(d)["sha256"], mi.build_stamp(d)["sha256"])

    def test_a_checkpoint_without_weights_still_gets_a_stamp(self):
        d = self.tmp / "senza-pesi"
        d.mkdir()
        (d / "config.json").write_text('{"id2label": {"0": "O"}}', "utf-8")

        timbro = mi.build_stamp(d)

        self.assertEqual(timbro["labels"], 1)
        self.assertIsNone(timbro["sha256"])


class TestLettura(TimbroTestCase):

    def test_what_is_written_is_what_is_read_back(self):
        d = _fai_checkpoint(self.tmp, "rizzo-pii-0.3B-security", b"pesi")

        scritto = mi.write_stamp(d, d / mi.STAMP_NAME)

        self.assertEqual(mi.read_stamp(d), scritto)

    def test_a_package_built_before_the_stamp_reports_unidentified(self):
        # None non e' un errore: e' 'non identificato'. Un pacchetto vecchio continua
        # a funzionare, e l'interfaccia lo dichiara invece di inventare un nome.
        d = _fai_checkpoint(self.tmp, "senza-timbro", b"pesi")

        self.assertIsNone(mi.read_stamp(d))

    def test_a_corrupt_stamp_is_unidentified_rather_than_fatal(self):
        d = _fai_checkpoint(self.tmp, "timbro-rotto", b"pesi")
        (d / mi.STAMP_NAME).write_text("{non json", "utf-8")

        self.assertIsNone(mi.read_stamp(d))

    def test_a_stamp_that_is_not_an_object_is_unidentified(self):
        d = _fai_checkpoint(self.tmp, "timbro-lista", b"pesi")
        (d / mi.STAMP_NAME).write_text("[1, 2]", "utf-8")

        self.assertIsNone(mi.read_stamp(d))


class TestEndpoint(TimbroTestCase):
    """GET /model: la risposta alla domanda 'quale dei due sto usando?'.

    Il modello e' stubbato come nel resto della suite: qui non interessa cosa predice,
    interessa che l'app dichiari la propria identita' e che dica 'non identificato'
    invece di inventarla."""

    def setUp(self):
        super().setUp()
        self.app = _app
        self._info = _app.MODEL_INFO
        self.client = _app.app.test_client()
        # Il numero atteso si chiede al modello caricato invece di fissarlo a 44: gli
        # stub della suite sono installati con setdefault, quindi quale vince dipende
        # dall'ordine di scoperta dei file. Un test che dipende da quell'ordine passa
        # da solo e fallisce nella suite — e' successo scrivendo questo file.
        cfg = _app.nlp.model.config
        self.etichette = len(getattr(cfg, "label2id", None) or {})

    def tearDown(self):
        _app.MODEL_INFO = self._info
        super().tearDown()

    def test_a_stamped_package_reports_which_checkpoint_it_is(self):
        d = _fai_checkpoint(self.tmp, "pii_model", b"pesi")
        mi.write_stamp(d, d / mi.STAMP_NAME, name="rizzo-pii-0.3B-security")
        _app.MODEL_INFO = mi.read_stamp(d)

        dati = self.client.get("/model").get_json()

        self.assertTrue(dati["identified"])
        self.assertEqual(dati["name"], "rizzo-pii-0.3B-security")
        # col timbro il conteggio viene dal timbro, non dal modello caricato: e' il
        # dato congelato al build, ed e' quello che identifica il checkpoint
        self.assertEqual(dati["labels"], 44)
        self.assertTrue(dati["sha256"])

    def test_without_a_stamp_it_says_so_instead_of_guessing_a_name(self):
        _app.MODEL_INFO = None

        dati = self.client.get("/model").get_json()

        self.assertFalse(dati["identified"])
        self.assertIsNone(dati["sha256"])

    def test_the_label_count_is_reported_even_without_a_stamp(self):
        # viene dal modello caricato, non dal timbro: e' l'unica cosa che si sa
        # comunque, e distingue un checkpoint compatibile da uno che non lo e'
        _app.MODEL_INFO = None

        self.assertEqual(self.client.get("/model").get_json()["labels"], self.etichette)

    def test_there_is_no_post(self):
        # il modello non si cambia a caldo: nlp e' costruito all'import e usato dentro
        # analyze() con Flask threaded=True
        self.assertEqual(self.client.post("/model").status_code, 405)


if __name__ == "__main__":
    unittest.main()
