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

class TestWordPieceRejoin(unittest.TestCase):
    """I token della validation sono WordPiece: `##x` continua la parola precedente.
    Unendoli tutti con uno spazio si otteneva `CA ##P` invece di `CAP`.

    Misurato prima della correzione: il 63,7% delle righe conteneva marcatori `##` e
    il 45,8% delle entita' del gold ne aveva uno DENTRO il proprio span. Il confronto
    A/B restava valido (stesso testo per entrambi), ma i valori assoluti descrivevano
    un testo che in produzione non esiste, e i quattro tag dichiarati deboli sono
    esattamente gli alfanumerici lunghi che WordPiece divide."""

    def test_continuation_pieces_are_glued_to_the_previous_token(self):
        out = ev.from_bio({"tokens": ["CA", "##P", ":", "900", "##20"],
                           "bio_labels": ["O", "O", "O", "B-ZIPCODE", "I-ZIPCODE"]})
        self.assertEqual(out["source_text"], "CAP : 90020")

    def test_the_entity_span_covers_the_whole_rejoined_word(self):
        out = ev.from_bio({"tokens": ["in", "900", "##20", "."],
                           "bio_labels": ["O", "B-ZIPCODE", "I-ZIPCODE", "O"]})
        e = out["entities"][0]
        self.assertEqual(out["source_text"][e["start"]:e["end"]], "90020")

    def test_offsets_agree_with_the_stored_value(self):
        out = ev.from_bio({"tokens": ["Son", "##ce", "##bo", "##z", "citta"],
                           "bio_labels": ["B-CITY", "I-CITY", "I-CITY", "I-CITY", "O"]})
        for e in out["entities"]:
            self.assertEqual(out["source_text"][e["start"]:e["end"]], e["value"])
        self.assertEqual(out["entities"][0]["value"], "Sonceboz")

    def test_ordinary_tokens_still_get_a_space(self):
        out = ev.from_bio({"tokens": ["Mario", "Rossi", "ha", "firmato"],
                           "bio_labels": ["B-GIVENNAME", "B-SURNAME", "O", "O"]})
        self.assertEqual(out["source_text"], "Mario Rossi ha firmato")

    def test_a_bare_double_hash_is_not_treated_as_a_continuation(self):
        # '##' da solo non ha un pezzo dopo il prefisso: attaccarlo produrrebbe uno
        # span di larghezza zero
        out = ev.from_bio({"tokens": ["a", "##", "b"], "bio_labels": ["O", "O", "O"]})
        self.assertIn("##", out["source_text"])

    def test_a_leading_continuation_has_nothing_to_attach_to(self):
        out = ev.from_bio({"tokens": ["##ab", "c"], "bio_labels": ["O", "O"]})
        self.assertTrue(out["source_text"].startswith("##ab"))


if __name__ == "__main__":
    unittest.main()


class TestLabelNormalisation(unittest.TestCase):
    """Senza rimappare, il gold e il modello parlano due lingue diverse."""

    TEXT = "Il perito Mario Rossi ha firmato."

    def test_adjacent_name_parts_become_one_fullname(self):
        raw = {ev.Entity(10, 15, "GIVENNAME"), ev.Entity(16, 21, "SURNAME")}
        self.assertEqual(ev.normalize_entities(raw, self.TEXT),
                         {ev.Entity(10, 21, "FULLNAME")})

    def test_entities_far_apart_are_not_merged(self):
        text = "Mario ha incontrato Rossi ieri."
        raw = {ev.Entity(0, 5, "GIVENNAME"), ev.Entity(20, 25, "SURNAME")}
        self.assertEqual(len(ev.normalize_entities(raw, text)), 2)

    def test_dropped_types_disappear(self):
        raw = {ev.Entity(0, 2, "TITLE"), ev.Entity(10, 15, "GIVENNAME")}
        self.assertEqual({e.label for e in ev.normalize_entities(raw, self.TEXT)},
                         {"FULLNAME"})

    def test_the_copied_tag_map_matches_the_training_one(self):
        # la copia esiste perche' train_pii.py importa torch; ma le copie divergono,
        # quindi qui si rilegge la fonte e si confronta
        import ast
        src = (ROOT / "src" / "training" / "train_pii.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        found = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ("TAG_MAP", "DROP_TYPES"):
                found[target.id] = ast.literal_eval(node.value)
        self.assertEqual(found["TAG_MAP"], ev.TAG_MAP)
        self.assertEqual(found["DROP_TYPES"], ev.DROP_TYPES)


class TestDeterminism(unittest.TestCase):
    """Una misura che non si riproduce non e' una misura.

    Entity contiene una stringa, quindi l'ordine di iterazione di un set di Entity
    dipende dall'hash, che Python randomizza a ogni processo. Con una chiave di
    ordinamento parziale i pari merito si risolvevano diversamente a ogni esecuzione:
    la stessa misura sullo stesso file dava 0.817, 0.819 e 0.822."""

    TEXT = "Il tecnico Mario Rossi e Anna Bianchi hanno firmato il verbale."

    def _entities(self):
        return {ev.Entity(11, 16, "GIVENNAME"), ev.Entity(17, 22, "SURNAME"),
                ev.Entity(25, 29, "GIVENNAME"), ev.Entity(30, 37, "SURNAME"),
                ev.Entity(11, 16, "FULLNAME")}

    def test_normalisation_does_not_depend_on_set_iteration_order(self):
        atteso = ev.normalize_entities(self._entities(), self.TEXT)
        for _ in range(30):
            # ricostruire il set cambia l'ordine di iterazione fra processi diversi;
            # dentro lo stesso processo si forza rimescolando l'input
            mescolato = set(sorted(self._entities(), key=lambda e: (e.end, e.label)))
            self.assertEqual(ev.normalize_entities(mescolato, self.TEXT), atteso)

    def test_the_sort_key_is_total(self):
        # due entita' con lo stesso start devono avere un ordine definito
        a, b = ev.Entity(0, 5, "IP"), ev.Entity(0, 9, "DOMAIN")
        chiave = lambda e: (e.start, e.end, e.label)
        self.assertNotEqual(chiave(a), chiave(b))
