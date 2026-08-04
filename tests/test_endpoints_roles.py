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


class TestDetectorsEndpoint(EndpointTestCase):
    """I pacchetti si accendono dall'interfaccia, e la policy resta coerente.

    Prima erano raggiungibili solo da PII_DETECTORS all'import o da --detectors, che
    nell'app desktop non passa da nessuna delle due: chi installava il pacchetto non
    poteva accendere i detector di sicurezza in nessun modo."""

    def test_get_reports_the_active_and_the_available_packs(self):
        app.enable_packs([])

        dati = self.client.get("/detectors").get_json()

        self.assertEqual(dati["packs"], [])
        self.assertIn("cyber", dati["available"])
        self.assertIn("IP", dati["pack_tags"]["cyber"])

    def test_turning_a_pack_on_makes_its_labels_part_of_the_taxonomy(self):
        app.enable_packs([])

        r = self.client.post("/detectors", json={"packs": "cyber"})

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["packs"], ["cyber"])
        self.assertIn("IP", app.known_tags())

    def test_after_turning_it_on_the_policy_accepts_its_labels(self):
        # la regressione precisa dell'ordine: known_tags() legge ACTIVE_DETECTORS,
        # quindi chiedendo la tassonomia prima di accendere, 'IP' sarebbe scartato
        app.enable_packs([])
        self.assertEqual(
            self.client.post("/policy", json={"profile": "full", "keep_tags": "IP"}).status_code,
            400)

        self.client.post("/detectors", json={"packs": "cyber"})

        self.assertEqual(
            self.client.post("/policy", json={"profile": "full", "keep_tags": "IP"}).status_code,
            200)

    def test_turning_it_off_drops_the_tags_that_left_the_taxonomy(self):
        # senza, il modale si ritroverebbe precompilato con un tag che lui stesso
        # rifiuterebbe al salvataggio: un modale non salvabile su un valore che
        # l'utente non ha scritto
        app.enable_packs(["cyber"])
        self.client.post("/policy", json={"profile": "full", "keep_tags": "IP,EMAIL"})

        r = self.client.post("/detectors", json={"packs": []})

        self.assertEqual(r.get_json()["dropped_tags"], ["IP"])
        self.assertNotIn("IP", app.POLICY.keep_tags)
        self.assertIn("EMAIL", app.POLICY.keep_tags)      # quelli validi restano

    def test_an_unknown_pack_is_refused_without_changing_anything(self):
        # enable_packs si limita a un avviso: ragionevole per una CLI, non per un'API.
        # E un refuso sbaglia nella direzione pericolosa - senza il pacchetto gli IP
        # restano in chiaro perche' nessuno li cerca.
        app.enable_packs(["cyber"])

        r = self.client.post("/detectors", json={"packs": "cybre"})

        self.assertEqual(r.status_code, 400)
        self.assertEqual(app.ACTIVE_PACKS, ("cyber",))

    def test_the_choice_is_remembered_for_the_next_startup(self):
        app.enable_packs([])

        self.client.post("/detectors", json={"packs": "cyber"})

        self.assertEqual(policy.saved_detectors(), ["cyber"])

    def test_the_profile_survives_the_switch(self):
        app.enable_packs([])
        self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})

        self.client.post("/detectors", json={"packs": "cyber"})

        self.assertEqual(app.POLICY.profile, "clinical")


class TestSecurityReportProfileIsHonest(EndpointTestCase):
    """Il profilo o funziona, o dice perche' non puo'.

    Con il pacchetto cyber spento le sue label non sono nella tassonomia, quindi
    resolve_roles le scarta e keep_roles esce VUOTO: il profilo diventa un sinonimo
    esatto di 'full', con un avviso che finisce in backend.log e che nessuno legge.
    Era selezionabile cosi' nell'app rilasciata.

    Il setUp della classe base accende cyber: qui si parte SPENTI di proposito, perche'
    e' la configurazione dell'app impacchettata."""

    def setUp(self):
        super().setUp()
        app.enable_packs([])
        app.POLICY = policy.Policy()

    def test_without_the_pack_the_profile_would_be_a_synonym_of_full(self):
        # la regressione documentata: si prova che il difetto esisteva, cosi' se
        # qualcuno rimuovesse l'attivazione automatica il test lo direbbe
        vuoto = policy.resolve_roles("security-report", None, app.known_tags(),
                                     warn=lambda _m: None)
        self.assertEqual(vuoto, policy.resolve_roles("full", None, app.known_tags(),
                                                     warn=lambda _m: None))

    def test_selecting_the_profile_enables_the_pack_it_needs(self):
        r = self.client.post("/policy", json={"profile": "security-report", "keep_tags": ""})

        self.assertEqual(r.get_json()["packs_enabled"], ["cyber"])
        self.assertIn("cyber", app.ACTIVE_PACKS)

    def test_its_role_rules_survive_the_taxonomy_filter(self):
        self.client.post("/policy", json={"profile": "security-report", "keep_tags": ""})

        self.assertTrue(app.POLICY.keeps("IP", scope.ROLE_ADVERSARY))
        # l'asimmetria che rende il profilo sicuro: cio' che e' del cliente, o di ruolo
        # non determinato, resta mascherato
        self.assertFalse(app.POLICY.keeps("IP", scope.ROLE_OWN))
        self.assertFalse(app.POLICY.keeps("IP", scope.ROLE_UNKNOWN))

    def test_the_response_says_the_scope_is_still_missing(self):
        # l'unico requisito che l'app non puo' soddisfare da sola: senza un file
        # d'ingaggio nessuna entita' ha un ruolo, quindi regole per ruolo non possono
        # applicarsi a niente
        r = self.client.post("/policy", json={"profile": "security-report", "keep_tags": ""})

        self.assertIn("scope", r.get_json()["unmet"])

    def test_a_profile_without_requirements_reports_nothing_unmet(self):
        r = self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})

        self.assertEqual(r.get_json()["unmet"], [])

    def test_choosing_another_profile_afterwards_does_not_turn_the_pack_off(self):
        # l'insieme attivo e' l'unione: un profilo accende cio' che gli serve e non
        # spegne mai cio' che l'utente aveva scelto
        self.client.post("/policy", json={"profile": "security-report", "keep_tags": ""})

        self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})

        self.assertIn("cyber", app.ACTIVE_PACKS)

    def test_a_rejected_save_does_not_leave_the_pack_enabled(self):
        """Una richiesta rifiutata non deve lasciare traccia.

        Il profilo accende i pacchetti PRIMA di validare i tag — deve, perche'
        known_tags() legge i detector attivi. Ma se poi la validazione fallisce, il
        file non viene scritto: senza ripristino i pacchetti restavano accesi in
        memoria mentre policy.json non ne sapeva nulla, cioe' stato in esecuzione e
        stato salvato divergenti. Trovato provando gli endpoint sul server vero."""
        r = self.client.post("/policy", json={"profile": "security-report",
                                              "keep_tags": "NONESISTE"})

        self.assertEqual(r.status_code, 400)
        self.assertEqual(app.ACTIVE_PACKS, ())
        self.assertEqual(policy.saved_detectors(), [])

    def test_get_policy_exposes_the_role_rules_of_every_profile(self):
        # senza, nella tendina 'security-report' e 'full' sono tipograficamente
        # identici: entrambi con l'elenco dei tag vuoto
        dati = self.client.get("/policy").get_json()

        self.assertIn("IP", dati["profile_roles"]["security-report"][scope.ROLE_ADVERSARY])
        self.assertEqual(dati["requires"]["security-report"]["packs"], ["cyber"])


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

    def test_a_policy_without_roles_does_not_grow_a_keep_roles_key(self):
        # un file senza quella chiave e' la configurazione di chi non usa i ruoli, non
        # un file a cui manca qualcosa. 'detectors' invece c'e' perche' il setUp
        # accende il pacchetto cyber, e salvare la policy registra i pacchetti attivi
        # perche' sopravvivano al riavvio.
        r = self.client.post("/policy", json={"profile": "clinical", "keep_tags": ""})

        self.assertNotIn("keep_roles", r.get_json())
        self.assertEqual(policy.load_file(),
                         {"profile": "clinical", "keep_tags": [], "detectors": ["cyber"]})

    def test_saving_from_the_ui_does_not_erase_the_active_detectors(self):
        # gemello del test sui keep_roles: il modale non espone i pacchetti nello
        # stesso POST, quindi salvare un profilo non deve spegnerli al prossimo avvio
        self.client.post("/policy", json={"profile": "full", "keep_tags": "EMAIL"})

        self.assertEqual(policy.saved_detectors(), ["cyber"])


if __name__ == "__main__":
    unittest.main()
