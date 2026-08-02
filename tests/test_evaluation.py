# -*- coding: utf-8 -*-
"""
Test dell'attrezzatura di valutazione: split disgiunti (src/data_pipeline/
generate_cyber_pii.py) e metriche entity-level (src/training/evaluate_entities.py).

Lo scopo dell'attrezzatura e' rispondere a una domanda sola prima di riaddestrare:
il modello sarebbe piu' affidabile della rete regex che gia' abbiamo? Perche' quella
risposta valga, le due partizioni devono essere davvero disgiunte e le metriche
devono misurare il sistema, non i suoi pezzi.

    python -m unittest discover -s tests
"""

import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))
sys.path.insert(0, str(ROOT / "src" / "training"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import evaluate_entities as ev     # noqa: E402
import generate_cyber_pii as cy    # noqa: E402

SAMPLES = 300


class PoolTestCase(unittest.TestCase):
    """set_value_pool e' stato di modulo: si ripristina sempre."""

    def tearDown(self):
        cy.set_value_pool("all")


class TestTemplateSplit(PoolTestCase):

    def test_the_split_is_stable_across_reorderings(self):
        # la banca cresce a ogni raccolta: uno split per indice rimescolerebbe tutto e
        # un template in valutazione oggi finirebbe nel training domani — leakage
        # invisibile fra due esecuzioni
        tpl = [f"Il {{DATE}} l'analista {{FULLNAME}} nota {i} su {{HOSTNAME}}."
               for i in range(200)]
        a_train, a_eval = cy.split_templates(tpl)
        b_train, b_eval = cy.split_templates(list(reversed(tpl)))
        self.assertEqual(set(a_train), set(b_train))
        self.assertEqual(set(a_eval), set(b_eval))

    def test_the_two_parts_are_disjoint_and_complete(self):
        tpl = [f"template numero {i} con {{IPADDR}}" for i in range(300)]
        train, ev_ = cy.split_templates(tpl)
        self.assertEqual(set(train) & set(ev_), set())
        self.assertEqual(len(train) + len(ev_), len(tpl))

    def test_roughly_the_requested_share_goes_to_eval(self):
        tpl = [f"template numero {i} con {{IPADDR}}" for i in range(1000)]
        _train, ev_ = cy.split_templates(tpl, eval_percent=20)
        self.assertGreater(len(ev_), 120)      # ~200 attesi, tolleranza ampia
        self.assertLess(len(ev_), 280)

    def test_the_same_template_always_lands_on_the_same_side(self):
        t = "Il {DATE} l'host {HOSTNAME} ha contattato {IPADDR}."
        self.assertEqual({cy.template_split(t) for _ in range(20)},
                         {cy.template_split(t)})


class TestValuePools(PoolTestCase):
    """Se i valori non sono disgiunti, la valutazione misura la memoria dei prefissi."""

    def _nets(self, pool, n=SAMPLES):
        cy.set_value_pool(pool)
        return {ipaddress.ip_network(f"{cy._ipv4()}/24", strict=False) for _ in range(n)}

    def test_train_and_eval_ip_ranges_do_not_overlap(self):
        train, ev_ = self._nets("train"), self._nets("eval")
        for a in train:
            for b in ev_:
                self.assertFalse(a.overlaps(b), f"{a} e {b} si sovrappongono")

    def test_train_and_eval_tlds_do_not_overlap(self):
        cy.set_value_pool("train")
        t = {cy._domain().rsplit(".", 1)[-1] for _ in range(SAMPLES)}
        cy.set_value_pool("eval")
        e = {cy._domain().rsplit(".", 1)[-1] for _ in range(SAMPLES)}
        self.assertEqual(t & e, set())

    def test_train_and_eval_asn_ranges_do_not_overlap(self):
        cy.set_value_pool("train")
        t = {int(cy.asn_piece()[0][0][2:]) for _ in range(SAMPLES)}
        cy.set_value_pool("eval")
        e = {int(cy.asn_piece()[0][0][2:]) for _ in range(SAMPLES)}
        self.assertEqual(t & e, set())

    def test_every_pool_stays_inside_the_documentation_spaces(self):
        # l'invariante di sicurezza non dipende da come si divide il campione
        for pool in cy.VALUE_POOLS:
            cy.set_value_pool(pool)
            for _ in range(SAMPLES):
                self.assertEqual(cy.in_documentation_space(cy._ipv4()), [], pool)
                self.assertTrue(cy._is_doc_domain(cy._domain()), pool)

    def test_an_unknown_pool_is_refused(self):
        with self.assertRaises(ValueError):
            cy.set_value_pool("inesistente")


class TestMetrics(unittest.TestCase):

    def test_perfect_prediction_scores_one(self):
        e = {ev.Entity(0, 5, "IP")}
        stat = ev.score([(e, e)])
        self.assertEqual(ev.prf(**stat["IP"]), (1.0, 1.0, 1.0))

    def test_a_missed_entity_lowers_recall_not_precision(self):
        stat = ev.score([({ev.Entity(0, 5, "IP"), ev.Entity(9, 14, "IP")},
                          {ev.Entity(0, 5, "IP")})])
        p, r, _f = ev.prf(**stat["IP"])
        self.assertEqual((r, p), (0.5, 1.0))

    def test_a_spurious_entity_lowers_precision_not_recall(self):
        stat = ev.score([({ev.Entity(0, 5, "IP")},
                          {ev.Entity(0, 5, "IP"), ev.Entity(9, 14, "IP")})])
        p, r, _f = ev.prf(**stat["IP"])
        self.assertEqual((r, p), (1.0, 0.5))

    def test_a_wrong_span_is_a_miss_not_a_partial_credit(self):
        # meta' FULLNAME lascia il cognome in chiaro: conta come mancato
        stat = ev.score([({ev.Entity(0, 11, "FULLNAME")},
                          {ev.Entity(0, 5, "FULLNAME")})])
        self.assertEqual((stat["FULLNAME"]["tp"], stat["FULLNAME"]["fn"],
                          stat["FULLNAME"]["fp"]), (0, 1, 1))

    def test_the_label_must_match_too(self):
        stat = ev.score([({ev.Entity(0, 5, "IP")}, {ev.Entity(0, 5, "DOMAIN")})])
        self.assertEqual(stat["IP"]["fn"], 1)
        self.assertEqual(stat["DOMAIN"]["fp"], 1)

    def test_empty_counts_do_not_divide_by_zero(self):
        self.assertEqual(ev.prf(0, 0, 0), (0.0, 0.0, 0.0))


class TestDetectorBaseline(unittest.TestCase):

    TEXT = "Scaricato da https://evil.example/x.bin verso 203.0.113.9."

    def test_merging_removes_the_domain_nested_in_a_url(self):
        # senza merge si misurano i detector grezzi invece del sistema: il dominio
        # dentro l'URL verrebbe contato come errore mentre nell'app l'URL vince
        grezzi = ev.detector_entities(self.TEXT, merge=False)
        sistema = ev.detector_entities(self.TEXT, merge=True)
        self.assertIn("DOMAIN", {e.label for e in grezzi})
        self.assertNotIn("DOMAIN", {e.label for e in sistema})
        self.assertIn("URL", {e.label for e in sistema})

    def test_the_label_filter_is_applied(self):
        only = ev.detector_entities(self.TEXT, labels={"IP"})
        self.assertEqual({e.label for e in only}, {"IP"})


if __name__ == "__main__":
    unittest.main()


class TestCidrPool(PoolTestCase):
    """Il pool delle reti CIDR e' dichiarato, non dedotto da is_private.

    Python considera privati anche gli intervalli documentali RFC 5737, quindi un
    filtro su is_private faceva finire 198.51.100.0/24 fra le reti "interne" di un
    documento — una rete di esempi presentata come rete aziendale."""

    def test_documentation_ranges_never_appear_as_internal_networks(self):
        doc = [ipaddress.ip_network(n) for n in cy.DOC_NETS_V4]
        for pool in cy.VALUE_POOLS:
            cy.set_value_pool(pool)
            for _ in range(200):
                sub = ipaddress.ip_network(cy.cidr_piece()[0][0])
                for d in doc:
                    self.assertFalse(sub.subnet_of(d), f"{pool}: {sub} dentro {d}")

    def test_train_and_eval_cidr_pools_do_not_overlap(self):
        cy.set_value_pool("train")
        t = {ipaddress.ip_network(cy.cidr_piece()[0][0]) for _ in range(200)}
        cy.set_value_pool("eval")
        e = {ipaddress.ip_network(cy.cidr_piece()[0][0]) for _ in range(200)}
        for a in t:
            for b in e:
                self.assertFalse(a.overlaps(b), f"{a} e {b}")
