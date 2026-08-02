# -*- coding: utf-8 -*-
"""
Endpoint HTTP che toccano ruoli e scope (src/app/app.py).

Due cose da dimostrare:

  1. GET /scope espone i CONTEGGI e mai i valori — quel file elenca gli indirizzi
     del cliente e gli indicatori dell'avversario.
  2. POST /policy non distrugge le regole per ruolo scritte a mano in policy.json:
     l'UI non le espone, quindi salvare dal modale non deve cancellarle.

Modello stubbato; config dir temporanea, i test non scrivono nella cartella
dell'utente. Valori dagli intervalli di documentazione (RFC 5737, RFC 2606).

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


class EndpointTestCase(unittest.TestCase):

    def setUp(self):
        self._packs, self._policy, self._scope = list(app.ACTIVE_PACKS), app.POLICY, app.SCOPE
        app.enable_packs(["cyber"])
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = policy.server_config.config_dir
        policy.server_config.config_dir = lambda: Path(self._tmp.name)
        self.client = app.app.test_client()

    def tearDown(self):
        policy.server_config.config_dir = self._orig_dir
        self._tmp.cleanup()
        app.enable_packs(self._packs)
        app.POLICY, app.SCOPE = self._policy, self._scope


class TestScopeEndpoint(EndpointTestCase):

    def test_get_reports_counts_and_never_the_values(self):
        app.SCOPE = scope.Scope(lists={scope.ROLE_OWN: {"IP": [CLIENT_IP, "10.0.0.0/8"]},
                                       scope.ROLE_ADVERSARY: {"DOMAIN": ["evil.example"]}})
        r = self.client.get("/scope")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["counts"], {scope.ROLE_OWN: {"IP": 2},
                                          scope.ROLE_ADVERSARY: {"DOMAIN": 1}})
        raw = json.dumps(body)
        self.assertNotIn(CLIENT_IP, raw)
        self.assertNotIn("evil.example", raw)

    def test_get_reports_whether_the_context_is_on(self):
        app.SCOPE = scope.Scope(context_roles=(scope.ROLE_ADVERSARY,))
        body = self.client.get("/scope").get_json()
        self.assertEqual(body["context_roles"], [scope.ROLE_ADVERSARY])
        self.assertEqual(body["counts"], {})

    def test_get_lists_the_assignable_roles(self):
        body = self.client.get("/scope").get_json()
        self.assertEqual(body["roles"], list(scope.ROLES))
        self.assertEqual(body["unknown_role"], scope.ROLE_UNKNOWN)

    def test_there_is_no_post(self):
        # scrivere lo scope da HTTP significherebbe far transitare gli IOC in un body
        self.assertEqual(self.client.post("/scope", json={}).status_code, 405)


class TestPolicyEndpointKeepsRoles(EndpointTestCase):

    def test_saving_from_the_ui_does_not_erase_hand_written_keep_roles(self):
        policy.save_file("full", [], {scope.ROLE_ADVERSARY: ["IP"]})
        r = self.client.post("/policy", json={"profile": "full", "keep_tags": "EMAIL"})
        self.assertEqual(r.status_code, 200)
        # sopravvive nel file...
        self.assertEqual(policy.load_file()["keep_roles"], {scope.ROLE_ADVERSARY: ["IP"]})
        # ...e nella policy attiva
        self.assertTrue(app.POLICY.keeps("IP", scope.ROLE_ADVERSARY))
        self.assertFalse(app.POLICY.keeps("IP", scope.ROLE_OWN))

    def test_switching_to_the_security_report_profile_activates_its_role_rules(self):
        r = self.client.post("/policy", json={"profile": "security-report", "keep_tags": ""})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(app.POLICY.keeps("IP", scope.ROLE_ADVERSARY))
        self.assertFalse(app.POLICY.keeps("IP", scope.ROLE_UNKNOWN))
        self.assertIn("keep_roles", r.get_json())

    def test_a_policy_without_roles_answers_exactly_as_before(self):
        r = self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})
        self.assertNotIn("keep_roles", r.get_json())
        self.assertEqual(policy.load_file(), {"profile": "clinical", "keep_tags": []})


if __name__ == "__main__":
    unittest.main()
