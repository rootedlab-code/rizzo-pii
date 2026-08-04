# -*- coding: utf-8 -*-
"""
Test d'integrazione fra i pacchetti di detector e la policy (src/app/app.py).

Verificano l'unico punto in cui i due si toccano: la tassonomia. Con un pacchetto
attivo le sue label devono essere accettate da --keep-tags; con il pacchetto spento
devono essere rifiutate, perche' quel tag non esiste in quella configurazione.

Modello sostituito da uno stub, come negli altri test d'integrazione.
Tutti i valori sono presi dagli intervalli di documentazione (RFC 5737 / RFC 2606).

    python -m unittest discover -s tests
"""

import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))

MODEL_LABELS = ("O", "B-FULLNAME", "I-FULLNAME", "B-EMAIL", "B-IBAN")


class _FakeNlp:
    """Pipeline finta: non rileva nulla, ma espone la tassonomia del modello."""

    def __init__(self):
        self.model = types.SimpleNamespace(config=types.SimpleNamespace(
            label2id={name: i for i, name in enumerate(MODEL_LABELS)}))

    def __call__(self, texts, *args, **kwargs):
        return [[] for _ in texts] if isinstance(texts, list) else []


def _install_stubs():
    torch = types.ModuleType("torch")
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    sys.modules.setdefault("torch", torch)

    transformers = types.ModuleType("transformers")
    transformers.pipeline = lambda *a, **k: _FakeNlp()
    sys.modules.setdefault("transformers", transformers)

    fitz = types.ModuleType("fitz")
    fitz.open = lambda *a, **k: None
    sys.modules.setdefault("fitz", fitz)


_install_stubs()

import app        # noqa: E402
import policy     # noqa: E402

SERVER_IP = "203.0.113.42"
TEXT = f"Il server di staging risponde su {SERVER_IP} e il dominio e' interno.example."


class PackPolicyTestCase(unittest.TestCase):
    """enable_packs() e la policy sono stato globale del modulo: si ripristina sempre."""

    def setUp(self):
        self._packs = list(app.ACTIVE_PACKS)
        self._policy = app.POLICY
        app.POLICY = policy.Policy()

    def tearDown(self):
        app.enable_packs(self._packs)
        app.POLICY = self._policy


class TestPubblicazioneAtomica(PackPolicyTestCase):
    """I detector attivi si pubblicano in un colpo solo, e sono immutabili.

    La stesura precedente assegnava le globali e poi le estendeva con `+=`, che su una
    lista modifica l'oggetto gia' visibile: con Flask in threaded=True un lettore
    concorrente poteva iterare una lista che cresceva sotto di lui e vedere mezzo
    pacchetto, senza alcun errore.

    Si asserisce la PROPRIETA' (immutabilita' e completezza), non si prova a vincere
    una gara fra thread: un test del genere sarebbe intermittente e misurerebbe lo
    scheduler invece del codice. E' lo stesso criterio di test_generate_cyber_pii, che
    afferma l'invariante su tutti i campioni invece di sperare nel caso giusto."""

    def test_the_active_detectors_are_immutable(self):
        app.enable_packs(["cyber"])

        for nome in ("ACTIVE_DETECTORS", "ACTIVE_KEEP", "ACTIVE_PACKS"):
            with self.subTest(globale=nome):
                self.assertIsInstance(getattr(app, nome), tuple)

    def test_turning_a_pack_on_publishes_the_complete_set_at_once(self):
        app.enable_packs([])
        soli_core = len(app.ACTIVE_DETECTORS)

        app.enable_packs(["cyber"])

        attesi = soli_core + len(app.DETECTOR_PACKS["cyber"][0])
        self.assertEqual(len(app.ACTIVE_DETECTORS), attesi)

    def test_turning_it_off_goes_back_to_the_core_exactly(self):
        app.enable_packs(["cyber"])

        app.enable_packs([])

        self.assertEqual(app.ACTIVE_DETECTORS, tuple(app.DETECTORS))
        self.assertEqual(app.ACTIVE_KEEP, ())
        self.assertEqual(app.ACTIVE_PACKS, ())

    def test_an_unknown_pack_leaves_the_known_ones_active(self):
        app.enable_packs(["cyber", "inesistente"])

        self.assertEqual(app.ACTIVE_PACKS, ("cyber",))


class TestTaxonomy(PackPolicyTestCase):

    def test_pack_labels_are_absent_when_the_pack_is_off(self):
        app.enable_packs([])
        self.assertNotIn("IP", app.known_tags())

    def test_pack_labels_join_the_taxonomy_when_the_pack_is_on(self):
        app.enable_packs(["cyber"])
        tags = app.known_tags()
        self.assertIn("IP", tags)
        self.assertIn("DOMAIN", tags)
        self.assertIn("FULLNAME", tags)      # quelle del modello restano

    def test_pack_label_is_rejected_by_the_policy_when_the_pack_is_off(self):
        app.enable_packs([])
        warnings = []
        pol = policy.load_policy(cli_keep_tags="IP", known_tags=app.known_tags(),
                                 warn=warnings.append)
        self.assertEqual(pol.keep_tags, frozenset())
        self.assertTrue(any("IP" in w for w in warnings))

    def test_pack_label_is_accepted_by_the_policy_when_the_pack_is_on(self):
        app.enable_packs(["cyber"])
        pol = policy.load_policy(cli_keep_tags="IP", known_tags=app.known_tags(),
                                 warn=lambda _m: None)
        self.assertEqual(pol.keep_tags, frozenset({"IP"}))


class TestAnalyze(PackPolicyTestCase):

    def entity_segments(self, out):
        return [s for s in out["segments"] if s.get("label")]

    def test_pack_entity_is_masked_by_default(self):
        app.enable_packs(["cyber"])
        out = app.analyze(TEXT)
        seg = next(s for s in self.entity_segments(out) if s["label"] == "IP")
        self.assertEqual(seg["action"], policy.ACTION_MASK)
        self.assertNotIn(SERVER_IP, out["anonymized_text"])
        self.assertIn(seg["ph"], out["mapping"])

    def test_pack_entity_stays_in_clear_when_the_policy_keeps_it(self):
        app.enable_packs(["cyber"])
        app.POLICY = policy.Policy(keep_tags=("IP",))
        out = app.analyze(TEXT)
        seg = next(s for s in self.entity_segments(out) if s["label"] == "IP")
        self.assertEqual(seg["action"], policy.ACTION_KEEP)
        self.assertEqual(seg["preservation_reason"], policy.REASON_CONFIG)
        self.assertIn(SERVER_IP, out["anonymized_text"])
        self.assertNotIn(SERVER_IP, out["mapping"].values())   # niente da ripristinare
        self.assertEqual(out["n_kept"], 1)


if __name__ == "__main__":
    unittest.main()
