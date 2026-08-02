# -*- coding: utf-8 -*-
"""
Test d'integrazione dello scope dentro analyze() (src/app/app.py).

Il test che conta e' uno solo, gli altri lo circondano: **lo stesso identico testo,
due file di scope diversi, esito opposto sullo stesso indirizzo**. E' la ragione per
cui esistono i ruoli — un asse per tag non puo' produrre due risposte diverse sulla
stessa stringa.

Modello sostituito da uno stub; rete regex, merge, placeholder e policy sono reali.
Valori dagli intervalli di documentazione (RFC 5737, RFC 2606).

    python -m unittest discover -s tests
"""

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))

MODEL_LABELS = ("O", "B-FULLNAME", "I-FULLNAME", "B-EMAIL")


class _FakeNlp:
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

import app     # noqa: E402
import policy  # noqa: E402
import scope   # noqa: E402

CLIENT_IP = "203.0.113.5"
TEXT = f"L'indirizzo {CLIENT_IP} compare nei log del 12 marzo."

# policy che tiene in chiaro gli IP dell'avversario e nient'altro
IOC_POLICY = policy.Policy(keep_roles={scope.ROLE_ADVERSARY: ["IP"]})


class AnalyzeScopeTestCase(unittest.TestCase):
    """Pacchetto cyber, policy e scope sono stato globale del modulo: si ripristina."""

    def setUp(self):
        self._packs, self._policy, self._scope = list(app.ACTIVE_PACKS), app.POLICY, app.SCOPE
        app.enable_packs(["cyber"])
        app.POLICY = IOC_POLICY
        app.SCOPE = scope.Scope()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        app.enable_packs(self._packs)
        app.POLICY, app.SCOPE = self._policy, self._scope
        self.tmp.cleanup()

    def use_scope_file(self, payload):
        """Scrive un file di scope e lo carica come farebbe PII_SCOPE_FILE."""
        path = Path(self.tmp.name) / "scope.json"
        path.write_text(json.dumps(payload), "utf-8")
        app.SCOPE = scope.load_scope(str(path))
        return path

    def ip_segment(self, out):
        return next(s for s in out["segments"] if s.get("label") == "IP")


class TestSameTextOppositeOutcome(AnalyzeScopeTestCase):
    """Il cuore del passo: cambia solo il file di scope, cambia l'esito."""

    def test_client_ip_is_masked(self):
        self.use_scope_file({"own": {"IP": [CLIENT_IP]}})
        out = app.analyze(TEXT)
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_OWN)
        self.assertEqual(seg["action"], policy.ACTION_MASK)
        self.assertNotIn(CLIENT_IP, out["anonymized_text"])
        self.assertIn(seg["ph"], out["mapping"])

    def test_the_very_same_ip_stays_in_clear_when_it_is_the_adversary(self):
        self.use_scope_file({"adversary": {"IP": [CLIENT_IP]}})
        out = app.analyze(TEXT)
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_ADVERSARY)
        self.assertEqual(seg["action"], policy.ACTION_KEEP)
        self.assertIn(CLIENT_IP, out["anonymized_text"])
        self.assertIsNone(seg["ph"])
        self.assertEqual(out["mapping"], {})      # niente da ripristinare

    def test_ip_in_no_list_is_unknown_and_therefore_masked(self):
        self.use_scope_file({"adversary": {"IP": ["198.51.100.7"]}})
        out = app.analyze(TEXT)
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_UNKNOWN)
        self.assertEqual(seg["action"], policy.ACTION_MASK)
        self.assertNotIn(CLIENT_IP, out["anonymized_text"])


class TestReasons(AnalyzeScopeTestCase):

    def test_kept_by_role_is_reported_as_scope(self):
        self.use_scope_file({"adversary": {"IP": [CLIENT_IP]}})
        seg = self.ip_segment(app.analyze(TEXT))
        self.assertEqual(seg["preservation_reason"], policy.REASON_SCOPE)
        self.assertEqual(seg["role_source"], scope.SOURCE_LIST)

    def test_kept_by_tag_is_reported_as_config_even_with_a_role(self):
        self.use_scope_file({"own": {"IP": [CLIENT_IP]}})
        app.POLICY = policy.Policy(keep_tags=["IP"])
        seg = self.ip_segment(app.analyze(TEXT))
        self.assertEqual(seg["preservation_reason"], policy.REASON_CONFIG)
        self.assertEqual(seg["role"], scope.ROLE_OWN)

    def test_role_from_context_is_reported_as_context(self):
        self.use_scope_file({"context": {"roles": ["adversary"]}})
        text = f"Il C2 risponde su {CLIENT_IP} ogni ora."
        out = app.analyze(text)                       # nessuna lista, solo indizi
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_ADVERSARY)
        self.assertEqual(seg["role_source"], scope.SOURCE_CONTEXT)
        self.assertIn(CLIENT_IP, out["anonymized_text"])

    def test_context_stays_off_until_it_is_declared(self):
        # stesso identico testo del test precedente, ma senza context.roles
        self.use_scope_file({})
        text = f"Il C2 risponde su {CLIENT_IP} ogni ora."
        out = app.analyze(text)
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_UNKNOWN)
        self.assertEqual(seg["action"], policy.ACTION_MASK)
        self.assertNotIn(CLIENT_IP, out["anonymized_text"])

    def test_an_explicit_list_beats_the_context_end_to_end(self):
        self.use_scope_file({"own": {"IP": [CLIENT_IP]},
                             "context": {"roles": ["adversary"]}})
        text = f"Il C2 risponde su {CLIENT_IP} ogni ora."
        seg = self.ip_segment(app.analyze(text))
        self.assertEqual(seg["role"], scope.ROLE_OWN)
        self.assertEqual(seg["role_source"], scope.SOURCE_LIST)
        self.assertEqual(seg["action"], policy.ACTION_MASK)


class TestResponse(AnalyzeScopeTestCase):

    def test_every_entity_carries_a_role(self):
        out = app.analyze(TEXT)
        for seg in (s for s in out["segments"] if s.get("label")):
            self.assertIn(seg["role"], (scope.ROLE_OWN, scope.ROLE_ADVERSARY,
                                        scope.ROLE_PUBLIC, scope.ROLE_UNKNOWN))

    def test_by_role_counts_the_entities(self):
        self.use_scope_file({"own": {"IP": [CLIENT_IP]}})
        self.assertEqual(app.analyze(TEXT)["by_role"], {scope.ROLE_OWN: 1})

    def test_response_carries_scope_counts_but_never_the_values(self):
        self.use_scope_file({"own": {"IP": [CLIENT_IP, "10.0.0.0/8"]}})
        out = app.analyze(TEXT)
        self.assertEqual(out["scope"]["counts"], {scope.ROLE_OWN: {"IP": 2}})
        self.assertNotIn(CLIENT_IP, json.dumps(out["scope"]))

    def test_without_a_scope_everything_is_unknown_and_masked(self):
        out = app.analyze(TEXT)                       # setUp lascia lo scope vuoto
        seg = self.ip_segment(out)
        self.assertEqual(seg["role"], scope.ROLE_UNKNOWN)
        self.assertEqual(seg["action"], policy.ACTION_MASK)
        self.assertEqual(out["scope"]["counts"], {})


if __name__ == "__main__":
    unittest.main()
