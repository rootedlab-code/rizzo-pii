# -*- coding: utf-8 -*-
"""
Test d'integrazione della policy dentro analyze() (src/app/app.py).

Il MODELLO e' sostituito da uno stub (e' una dipendenza esterna, non il codice sotto
esame): restano reali la rete regex+checksum, il merge e l'assegnazione dei placeholder.
Cosi' il test gira senza torch/transformers e senza scaricare il checkpoint.

    python -m unittest discover -s tests
"""

import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import modello_finto   # noqa: E402

MODEL_LABELS = ("O", "B-FULLNAME", "I-FULLNAME", "B-AGE", "B-GENDER", "B-DATE", "B-TIME",
                "B-AMOUNT", "B-EMAIL", "B-IBAN", "B-CF")


class _FakeNlp:
    """Pipeline di token-classification finta: non trova nulla, ma espone la stessa
    tassonomia del modello vero (serve a known_tags())."""

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

import app  # noqa: E402
import policy  # noqa: E402

EMAIL = "mario.rossi@studiolegale.it"
IBAN = "IT60X0542811101000000123456"
TEXT = (f"Per ogni comunicazione scrivere a {EMAIL}; il pagamento di € 12.500,00 "
        f"va effettuato sull'IBAN {IBAN}.")


class AnalyzeTestCase(unittest.TestCase):
    """Isola lo stato globale del modulo `app`: policy E pacchetti di detector.

    I pacchetti sono entrati qui il 2026-08-04. Prima questa classe si limitava alla
    policy, e i test funzionavano solo perche' nessuno li salvava: da quando salvare la
    policy registra anche i detector attivi, un pacchetto lasciato acceso da un ALTRO
    file di test comparirebbe in policy.json e cambierebbe il risultato di test che non
    lo nominano nemmeno. Era una dipendenza dall'ordine gia' presente e invisibile."""

    def setUp(self):
        self._orig = app.POLICY
        self._packs = list(app.ACTIVE_PACKS)
        app.POLICY = policy.Policy()          # default: maschera tutto
        app.enable_packs([])                  # default: solo la rete core

    def tearDown(self):
        app.POLICY = self._orig
        app.enable_packs(self._packs)

    def entity_segments(self, out):
        return [s for s in out["segments"] if s.get("label")]

    def segment_for(self, out, label):
        return next(s for s in self.entity_segments(out) if s["label"] == label)


class TestDefaultPolicy(AnalyzeTestCase):

    def test_everything_is_masked_and_reversible(self):
        out = app.analyze(TEXT)
        self.assertNotIn(EMAIL, out["anonymized_text"])
        self.assertNotIn(IBAN, out["anonymized_text"])
        self.assertIn("[EMAIL_1]", out["anonymized_text"])
        self.assertEqual(out["mapping"]["[EMAIL_1]"], EMAIL)
        self.assertEqual(out["mapping"]["[IBAN_1]"], IBAN)
        self.assertEqual(out["n_kept"], 0)

    def test_every_segment_declares_the_mask_action(self):
        out = app.analyze(TEXT)
        for seg in self.entity_segments(out):
            self.assertEqual(seg["action"], policy.ACTION_MASK)
            self.assertNotIn("preservation_reason", seg)

    def test_identical_values_share_one_placeholder(self):
        out = app.analyze(f"{EMAIL} e ancora {EMAIL}")
        self.assertEqual(out["n_entities"], 2)
        self.assertEqual(out["n_unique"], 1)


class TestKeepPolicy(AnalyzeTestCase):

    def test_kept_tag_stays_in_clear_and_out_of_the_dictionary(self):
        app.POLICY = policy.Policy(keep_tags=["EMAIL"])
        out = app.analyze(TEXT)
        self.assertIn(EMAIL, out["anonymized_text"])          # in chiaro
        self.assertNotIn(IBAN, out["anonymized_text"])        # mascherato
        self.assertNotIn("[EMAIL_1]", out["anonymized_text"])
        self.assertNotIn(EMAIL, out["mapping"].values())
        self.assertEqual(out["n_kept"], 1)

    def test_kept_entity_is_still_reported_with_its_reason(self):
        app.POLICY = policy.Policy(keep_tags=["EMAIL"])
        out = app.analyze(TEXT)
        seg = self.segment_for(out, "EMAIL")
        self.assertEqual(seg["action"], policy.ACTION_KEEP)
        self.assertEqual(seg["preservation_reason"], policy.REASON_CONFIG)
        self.assertEqual(seg["t"], EMAIL)
        self.assertIsNone(seg["ph"])
        self.assertEqual(out["by_label"]["EMAIL"], 1)         # rilevata, non nascosta

    def test_masked_entities_keep_working_next_to_a_kept_one(self):
        app.POLICY = policy.Policy(keep_tags=["EMAIL"])
        out = app.analyze(TEXT)
        self.assertEqual(out["mapping"]["[IBAN_1]"], IBAN)
        self.assertEqual(self.segment_for(out, "IBAN")["action"], policy.ACTION_MASK)

    def test_response_declares_the_active_policy(self):
        app.POLICY = policy.Policy(keep_tags=["AMOUNT"], profile="compare-amounts")
        out = app.analyze(TEXT)
        self.assertEqual(out["policy"],
                         {"profile": "compare-amounts", "keep_tags": ["AMOUNT"]})
        self.assertIn("€ 12.500,00", out["anonymized_text"])

    def test_text_is_unchanged_when_every_detected_tag_is_kept(self):
        app.POLICY = policy.Policy(keep_tags=["EMAIL", "IBAN", "AMOUNT"])
        out = app.analyze(TEXT)
        self.assertEqual(out["anonymized_text"], TEXT)
        self.assertEqual(out["mapping"], {})


class TestPolicyEndpoint(AnalyzeTestCase):
    """Endpoint /policy con il test client di Flask. La config dir e' temporanea:
    i test non scrivono nella cartella di configurazione dell'utente."""

    def setUp(self):
        super().setUp()
        # la tassonomia esposta da /policy e' modello + rete: il modello va imposto,
        # altrimenti si asserisce su quello del primo file di test importato
        modello_finto.imponi(self, app, MODEL_LABELS)
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = policy.server_config.config_dir
        policy.server_config.config_dir = lambda: Path(self._tmp.name)
        self.client = app.app.test_client()

    def tearDown(self):
        policy.server_config.config_dir = self._orig_dir
        self._tmp.cleanup()
        super().tearDown()

    def test_get_reports_profiles_and_taxonomy(self):
        body = self.client.get("/policy").get_json()
        self.assertEqual(body["profile"], policy.DEFAULT_PROFILE)
        self.assertIn("clinical", body["profiles"])
        # GENDER e non EMAIL: EMAIL lo produce anche la rete core, quindi passerebbe
        # pure con un modello senza tassonomia e non proverebbe niente sul modello
        self.assertIn("GENDER", body["known_tags"])      # solo dal modello (stub)
        self.assertIn("TARGA", body["known_tags"])       # solo dalla rete regex

    def test_post_applies_immediately_and_persists(self):
        r = self.client.post("/policy", json={"profile": "full", "keep_tags": "EMAIL"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app.POLICY.keep_tags, frozenset({"EMAIL"}))
        self.assertEqual(policy.load_file(), {"profile": "full", "keep_tags": ["EMAIL"]})
        out = self.client.post("/analyze", json={"text": TEXT}).get_json()
        self.assertIn(EMAIL, out["anonymized_text"])

    def test_post_rejects_unknown_tag_without_changing_anything(self):
        r = self.client.post("/policy", json={"profile": "full", "keep_tags": "NONESISTE"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("NONESISTE", r.get_json()["error"])
        self.assertEqual(app.POLICY.keep_tags, frozenset())
        self.assertEqual(policy.load_file(), {})         # niente scritto su disco

    def test_post_rejects_unknown_profile(self):
        r = self.client.post("/policy", json={"profile": "inesistente"})
        self.assertEqual(r.status_code, 400)

    def test_analyze_response_carries_the_policy(self):
        self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})
        out = self.client.post("/analyze", json={"text": TEXT}).get_json()
        self.assertEqual(out["policy"]["profile"], "clinical")


if __name__ == "__main__":
    unittest.main()


class TestAdjacentSpansAreFused(unittest.TestCase):
    """Il modello frammenta: 'Giulia Moretti' usciva come [FULLNAME_1] [FULLNAME_2],
    che per un LLM a valle sono due persone diverse.

    Il difetto era invisibile perche' normalize_entities() in valutazione FONDE gia',
    mentre _merge() nell'app no: la misura diceva 'FULLNAME migliora' e il prodotto
    peggiorava. Misurato su 2.000 righe: FULLNAME spezzato nel 9,9% dei casi."""

    def fondi(self, ents, testo):
        return [(e["label"], testo[e["start"]:e["end"]])
                for e in app._fuse_adjacent(ents, testo)]

    def ent(self, start, end, label, validated=False, source="modello"):
        return {"label": label, "start": start, "end": end, "score": 0.9,
                "validated": validated, "source": source}

    def test_two_adjacent_model_spans_become_one(self):
        testo = "Giulia Moretti ha firmato"
        fusi = self.fondi([self.ent(0, 6, "FULLNAME"), self.ent(7, 14, "FULLNAME")], testo)
        self.assertEqual(fusi, [("FULLNAME", "Giulia Moretti")])

    def test_a_different_label_is_not_fused(self):
        testo = "Roma Milano"
        fusi = self.fondi([self.ent(0, 4, "CITY"), self.ent(5, 11, "ORG")], testo)
        self.assertEqual(len(fusi), 2)

    def test_words_in_between_block_the_fusion(self):
        # 'Mario Rossi e Luigi Bianchi' sono due persone: la 'e' lo dice
        testo = "Mario e Luigi"
        fusi = self.fondi([self.ent(0, 5, "FULLNAME"), self.ent(8, 13, "FULLNAME")], testo)
        self.assertEqual(len(fusi), 2)

    def test_validated_spans_are_never_fused(self):
        # due IP accanto sono due indirizzi, non uno lungo: fonderli li mascherebbe
        # con un solo segnaposto e il dizionario perderebbe che erano distinti
        testo = "203.0.113.1 203.0.113.2"
        fusi = self.fondi([self.ent(0, 11, "IP", validated=True, source="regex"),
                           self.ent(12, 23, "IP", validated=True, source="regex")], testo)
        self.assertEqual(len(fusi), 2)

    def test_three_fragments_collapse_into_one(self):
        testo = "Maria Teresa Bianchi"
        fusi = self.fondi([self.ent(0, 5, "FULLNAME"), self.ent(6, 12, "FULLNAME"),
                           self.ent(13, 20, "FULLNAME")], testo)
        self.assertEqual(fusi, [("FULLNAME", "Maria Teresa Bianchi")])

    def test_a_newline_between_them_still_fuses(self):
        testo = "Giulia\nMoretti"
        fusi = self.fondi([self.ent(0, 6, "FULLNAME"), self.ent(7, 14, "FULLNAME")], testo)
        self.assertEqual(len(fusi), 1)

    def test_the_end_to_end_result_has_one_placeholder_per_name(self):
        r = app.analyze("l'analista Giulia Moretti ha isolato l'host")
        nomi = [s for s in r["segments"] if s.get("label") == "FULLNAME"]
        self.assertLessEqual(len(nomi), 1)
