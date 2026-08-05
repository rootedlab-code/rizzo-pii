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

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import modello_finto   # noqa: E402

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
import scope      # noqa: E402

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


class TestPrecedenzaDeiPacchetti(unittest.TestCase):
    """CLI > PII_DETECTORS > policy.json > nessuno.

    Senza persistenza l'utente desktop dovrebbe ri-accendere i detector a ogni avvio,
    cioe' il problema non sarebbe risolto. Il posto e' policy.json e non config.json:
    quest'ultimo e' riscritto per intero da Tauri e da POST /config, e cancellerebbe
    la chiave al primo salvataggio di host e porta."""

    def setUp(self):
        self._env = {k: os.environ.pop(k) for k in ("PII_DETECTORS",) if k in os.environ}
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = policy.server_config.config_dir
        policy.server_config.config_dir = lambda: Path(self._tmp.name)

    def tearDown(self):
        policy.server_config.config_dir = self._orig
        self._tmp.cleanup()
        os.environ.pop("PII_DETECTORS", None)
        os.environ.update(self._env)

    def test_nothing_configured_means_no_pack(self):
        self.assertEqual(app.resolve_packs(), [])

    def test_the_saved_detectors_are_used_when_the_environment_is_silent(self):
        policy.save_file("full", (), detectors=["cyber"])

        self.assertEqual(app.resolve_packs(), ["cyber"])

    def test_the_environment_beats_the_saved_detectors(self):
        policy.save_file("full", (), detectors=["cyber"])
        os.environ["PII_DETECTORS"] = ""      # esplicitamente vuoto = nessun pacchetto

        # una env vuota non e' una scelta: la catena prosegue, come per host/porta
        self.assertEqual(app.resolve_packs(), ["cyber"])

    def test_the_cli_beats_everything(self):
        policy.save_file("full", (), detectors=["cyber"])
        os.environ["PII_DETECTORS"] = "cyber"

        self.assertEqual(app.resolve_packs(cli=""), ["cyber"])
        self.assertEqual(app.resolve_packs(cli="cyber"), ["cyber"])

    def test_saving_the_policy_without_detectors_writes_no_such_key(self):
        # un file senza quella chiave e' la configurazione di chi non usa i pacchetti,
        # non un file a cui manca qualcosa
        policy.save_file("full", ("AGE",))

        self.assertNotIn("detectors", policy.load_file())
        self.assertEqual(policy.saved_detectors(), [])

    def test_the_saved_detectors_survive_a_round_trip(self):
        policy.save_file("security-report", ("AGE",), detectors=["cyber"])

        self.assertEqual(policy.saved_detectors(), ["cyber"])
        self.assertEqual(policy.load_file()["profile"], "security-report")


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
    """La tassonomia e' modello + rete attiva, quindi qui il modello va imposto.

    `app.nlp` e' uno per processo e lo installa il primo file di test importato: senza
    `imponi`, `assertIn("FULLNAME", ...)` passava nella suite intera e falliva in ordine
    inverso, dove vince lo stub di `test_ui` che non ha label."""

    def setUp(self):
        super().setUp()
        modello_finto.imponi(self, app, MODEL_LABELS)

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

    def test_the_result_says_which_packs_produced_it(self):
        # senza, due esecuzioni identiche nell'aspetto possono venire da due
        # configurazioni diverse, e chi riporta un risultato non sa su cosa l'ha avuto
        app.enable_packs(["cyber"])
        self.assertEqual(app.analyze(TEXT)["packs"], ["cyber"])

        app.enable_packs([])
        self.assertEqual(app.analyze(TEXT)["packs"], [])

    def test_the_reported_packs_are_the_ones_the_detectors_came_from(self):
        """La fotografia deve comprendere i DETECTOR, non solo la policy.

        detect_regex() leggeva la globale mentre il resto dell'analisi usava lo scatto,
        e i 'packs' della risposta erano riletti alla fine: un /detectors arrivato a
        meta' documento cambiava cosa veniva cercato e cosa la risposta dichiarava, in
        due momenti diversi. Qui si prova la coerenza fra i due."""
        app.enable_packs(["cyber"])

        out = app.analyze(TEXT)

        etichette = {s["label"] for s in self.entity_segments(out)}
        self.assertEqual(out["packs"], ["cyber"])
        self.assertIn("IP", etichette)          # il pacchetto dichiarato ha davvero agito

    def test_the_reported_policy_is_the_one_the_segments_obey(self):
        # la policy si cambia a caldo da /policy mentre un'analisi e' in corso: senza
        # la fotografia presa in cima, meta' documento seguirebbe una regola e meta'
        # un'altra, e il campo 'policy' non descriverebbe nessuna delle due
        app.enable_packs(["cyber"])
        app.POLICY = policy.Policy(keep_tags=("IP",))

        out = app.analyze(TEXT)

        tenuti = set(out["policy"]["keep_tags"])
        for seg in self.entity_segments(out):
            atteso = policy.ACTION_KEEP if seg["label"] in tenuti else policy.ACTION_MASK
            with self.subTest(label=seg["label"]):
                self.assertEqual(seg["action"], atteso)


class TestAvvioDaRigaDiComando(PackPolicyTestCase):
    """Da terminale il profilo deve valere quanto vale nell'interfaccia.

    `POST /policy` accende i pacchetti che il profilo dichiara e dice cosa resta
    scoperto; l'avvio da riga di comando non faceva ne' l'una ne' l'altra cosa, quindi
    'security-report' restava un sinonimo silenzioso di 'full' per chi non passava anche
    --detectors cyber. Qui si parte a pacchetti SPENTI di proposito: e' la configurazione
    con cui parte l'app impacchettata."""

    def setUp(self):
        super().setUp()
        app.enable_packs([])
        self._env = {k: os.environ.pop(k)
                     for k in ("PII_PROFILE", "PII_KEEP_TAGS", "PII_SCOPE_FILE")
                     if k in os.environ}
        self._tmp = tempfile.TemporaryDirectory()
        self._config_dir = policy.server_config.config_dir
        policy.server_config.config_dir = lambda: Path(self._tmp.name)
        self._scope = app.SCOPE
        app.SCOPE = scope.load_scope(None)          # nessun ingaggio caricato

    def tearDown(self):
        app.SCOPE = self._scope
        policy.server_config.config_dir = self._config_dir
        self._tmp.cleanup()
        os.environ.update(self._env)
        super().tearDown()

    def test_the_regression_it_closes(self):
        # si prova che il difetto esisteva: a pacchetto spento le label del profilo non
        # sono nella tassonomia, resolve_roles le scarta e non resta nessuna regola
        muto = policy.load_policy(cli_profile="security-report",
                                  known_tags=app.known_tags(), warn=lambda _m: None)

        self.assertEqual(muto.keep_roles, {})

    def test_the_profile_turns_on_the_pack_it_needs(self):
        _pol, accesi = app.policy_di_avvio(cli_profile="security-report")

        self.assertEqual(accesi, ["cyber"])
        self.assertIn("cyber", app.ACTIVE_PACKS)

    def test_its_role_rules_survive_the_taxonomy_filter(self):
        pol, _accesi = app.policy_di_avvio(cli_profile="security-report")

        self.assertTrue(pol.keeps("IP", scope.ROLE_ADVERSARY))
        # l'asimmetria che rende il profilo sicuro: cio' che e' del cliente, o di ruolo
        # non determinato, resta mascherato
        self.assertFalse(pol.keeps("IP", scope.ROLE_OWN))
        self.assertFalse(pol.keeps("IP", scope.ROLE_UNKNOWN))

    def test_a_profile_that_comes_from_the_file_turns_it_on_too(self):
        # il motivo del doppio passaggio: il profilo puo' non venire dalla CLI, e quale
        # sia lo sa solo load_policy
        policy.save_file("security-report", ())

        _pol, accesi = app.policy_di_avvio()

        self.assertEqual(accesi, ["cyber"])

    def test_a_profile_without_requirements_turns_on_nothing(self):
        _pol, accesi = app.policy_di_avvio(cli_profile="clinical")

        self.assertEqual(accesi, [])
        self.assertEqual(app.ACTIVE_PACKS, ())

    def test_the_pack_chosen_on_the_command_line_is_not_turned_off(self):
        # l'insieme attivo e' l'unione: un profilo accende cio' che gli serve e non
        # spegne mai cio' che l'utente aveva chiesto
        app.enable_packs(["cyber"])

        _pol, accesi = app.policy_di_avvio(cli_profile="clinical")

        self.assertEqual(accesi, [])
        self.assertIn("cyber", app.ACTIVE_PACKS)

    def test_without_an_engagement_file_the_command_line_says_so(self):
        app.policy_di_avvio(cli_profile="security-report")

        avviso = app.avviso_requisiti("security-report")

        self.assertIsNotNone(avviso)
        self.assertIn("--scope-file", avviso)

    def test_with_an_engagement_file_there_is_nothing_to_declare(self):
        percorso = Path(self._tmp.name) / "ingaggio.json"
        percorso.write_text(json.dumps({"own": {"IP": ["203.0.113.0/24"]}}),
                            encoding="utf-8")
        app.SCOPE = scope.load_scope(str(percorso))
        app.policy_di_avvio(cli_profile="security-report")

        self.assertIsNone(app.avviso_requisiti("security-report"))

    def test_a_profile_without_requirements_declares_nothing(self):
        self.assertIsNone(app.avviso_requisiti("full"))


if __name__ == "__main__":
    unittest.main()
