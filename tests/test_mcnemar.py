# -*- coding: utf-8 -*-
"""
Test del confronto appaiato (src/training/mcnemar.py).

E' lo strumento con cui docs/CRITERIO.md decide se il modello addestrato sostituisce
quello in produzione, e la decisione si prende **una volta sola** sul test congelato:
un difetto qui non si scopre a una seconda esecuzione, perche' una seconda
esecuzione non e' prevista.

I valori attesi del test esatto sono calcolati a mano dalla binomiale, non presi da
un'altra implementazione: due implementazioni che concordano non dimostrano che una
delle due abbia ragione.

    python -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "training"))

import mcnemar as mc      # noqa: E402


class TestExactPValue(unittest.TestCase):

    def test_no_discordance_is_no_evidence(self):
        # nessuna discordanza: i due sistemi hanno gli stessi esiti ovunque
        self.assertEqual(mc.mcnemar_exact(0, 0), 1.0)

    def test_a_perfect_split_is_the_least_surprising_outcome(self):
        self.assertEqual(mc.mcnemar_exact(5, 5), 1.0)

    def test_all_discordances_on_one_side(self):
        # 10 discordanze tutte da una parte: p = 2 * (1/2)^10 = 1/512
        self.assertAlmostEqual(mc.mcnemar_exact(10, 0), 2 / 1024, places=12)

    def test_a_known_asymmetric_case(self):
        # n=10, k=2: 2 * (C(10,0)+C(10,1)+C(10,2)) / 2^10 = 2 * 56/1024
        self.assertAlmostEqual(mc.mcnemar_exact(8, 2), 2 * 56 / 1024, places=12)

    def test_it_is_symmetric_in_its_arguments(self):
        # scambiare A con B non puo' cambiare se sono distinguibili
        for a, b in ((7, 3), (12, 1), (0, 4), (30, 25)):
            self.assertEqual(mc.mcnemar_exact(a, b), mc.mcnemar_exact(b, a))

    def test_a_single_discordance_never_reaches_significance(self):
        # p = 2 * 1/2 = 1.0: con una sola discordanza non si conclude nulla
        self.assertEqual(mc.mcnemar_exact(1, 0), 1.0)

    def test_the_probability_never_exceeds_one(self):
        # il raddoppio della coda puo' sforare: va tagliato, o si stampa "p = 1.6"
        for a in range(0, 12):
            for b in range(0, 12):
                self.assertLessEqual(mc.mcnemar_exact(a, b), 1.0)
                self.assertGreater(mc.mcnemar_exact(a, b), 0.0)

    def test_more_lopsided_means_smaller_p(self):
        totale = 20
        precedente = 1.1
        for k in range(totale // 2, -1, -1):
            p = mc.mcnemar_exact(totale - k, k)
            self.assertLess(p, precedente)
            precedente = p


class TestPairedComparison(unittest.TestCase):

    def esiti(self, etichette, valori):
        return list(zip(etichette, valori))

    def test_it_counts_the_two_directions_separately(self):
        et = ["FULLNAME"] * 6
        a = self.esiti(et, [True, True, True, False, False, False])
        b = self.esiti(et, [True, False, False, True, False, False])
        rec_a, rec_b, solo_a, solo_b, _p = mc.confronta(a, b)
        self.assertEqual((rec_a, rec_b), (3, 2))
        self.assertEqual((solo_a, solo_b), (2, 1))

    def test_identical_systems_are_indistinguishable(self):
        a = self.esiti(["DATE"] * 4, [True, False, True, False])
        _ra, _rb, solo_a, solo_b, p = mc.confronta(a, list(a))
        self.assertEqual((solo_a, solo_b), (0, 0))
        self.assertEqual(p, 1.0)

    def test_misaligned_lists_are_refused_rather_than_compared(self):
        # confrontare due liste che non riguardano le stesse entita' produce un
        # numero perfettamente formato e privo di significato: e' il difetto che
        # questo controllo esiste per rendere impossibile
        a = self.esiti(["DATE", "IBAN"], [True, True])
        b = self.esiti(["IBAN", "DATE"], [True, True])
        with self.assertRaises(ValueError):
            mc.confronta(a, b)

    def test_lists_of_different_length_are_refused(self):
        a = self.esiti(["DATE", "IBAN"], [True, True])
        b = self.esiti(["DATE"], [True])
        with self.assertRaises(ValueError):
            mc.confronta(a, b)


class TestRuleBSweep(unittest.TestCase):
    """La regola B parla di OGNI tag sopra la soglia. Verificarla a mano, un tag per
    invocazione, significa in pratica verificare i tre che si sospettano gia'."""

    def esiti(self, spec):
        """spec: {tag: [(trovata_da_A, trovata_da_B), ...]}"""
        a, b = [], []
        for tag, coppie in spec.items():
            for x, y in coppie:
                a.append((tag, x))
                b.append((tag, y))
        return a, b

    def test_a_tag_that_only_loses_is_flagged(self):
        spec = {"ID_DOC": [(True, False)] * 12 + [(False, True)] * 2 +
                          [(True, True)] * 196}
        righe = mc.per_tag(*self.esiti(spec), 100)
        (lab, gold, _ra, _rb, solo_a, solo_b, p, decide), = righe
        self.assertEqual((lab, gold, solo_a, solo_b, decide),
                         ("ID_DOC", 210, 12, 2, True))
        self.assertLess(p, 0.05)

    def test_a_small_tag_is_reported_but_does_not_decide(self):
        spec = {"ZIPCODE": [(True, False)] * 9 + [(False, True)] * 4 +
                           [(True, True)] * 74}
        (_lab, gold, _ra, _rb, _sa, _sb, _p, decide), = mc.per_tag(*self.esiti(spec), 100)
        self.assertEqual(gold, 87)
        self.assertFalse(decide)

    def test_every_tag_appears_not_only_the_suspected_ones(self):
        spec = {f"TAG{i}": [(True, True)] * (100 + i) for i in range(16)}
        righe = mc.per_tag(*self.esiti(spec), 100)
        self.assertEqual(len(righe), 16)

    def test_rows_are_ordered_by_gold_count(self):
        spec = {"PICCOLO": [(True, True)] * 5, "GRANDE": [(True, True)] * 500,
                "MEDIO": [(True, True)] * 50}
        conteggi = [r[1] for r in mc.per_tag(*self.esiti(spec), 100)]
        self.assertEqual(conteggi, sorted(conteggi, reverse=True))

    def test_a_tag_that_only_gains_is_not_a_violation(self):
        spec = {"CATASTO": [(False, True)] * 78 + [(True, True)] * 267}
        peggiorati = mc.stampa_per_tag(mc.per_tag(*self.esiti(spec), 100), 100, 0.05)
        self.assertEqual(peggiorati, [])

    def test_the_verdict_lists_only_the_violating_tags(self):
        spec = {"BUONO": [(False, True)] * 50 + [(True, True)] * 150,
                "CATTIVO": [(True, False)] * 20 + [(True, True)] * 180}
        peggiorati = mc.stampa_per_tag(mc.per_tag(*self.esiti(spec), 100), 100, 0.05)
        self.assertEqual(peggiorati, ["CATTIVO"])


class TestParser(unittest.TestCase):

    def test_the_core_regex_net_is_the_default_not_the_cyber_pack(self):
        # il confronto di regressione si fa nella condizione di PRODUZIONE del
        # dominio legale, dove il pacchetto cyber e' spento
        args = mc.build_parser().parse_args(["g.jsonl", "--a", "a.jsonl", "--b", "b.jsonl"])
        self.assertEqual(args.packs, "")
        self.assertFalse(args.no_normalize)

    def test_the_limit_is_shared_by_both_predictions(self):
        args = mc.build_parser().parse_args(
            ["g.jsonl", "--a", "a.jsonl", "--b", "b.jsonl", "--limit", "2000"])
        self.assertEqual(args.limit, 2000)


if __name__ == "__main__":
    unittest.main()
