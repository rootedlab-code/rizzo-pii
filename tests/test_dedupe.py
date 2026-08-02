# -*- coding: utf-8 -*-
"""
Test della deduplicazione (src/data_pipeline/generate_cyber_pii.py).

Riproduce le prime due regole della pipeline di pulizia del progetto, documentate
nella card di rizzoaiacademy/anonimizzazione-testi-italiano-clean e NON presenti
nel repo: deduplicazione esatta di source_text, poi cap a N righe per scheletro.

Lo scheletro e' il testo con i valori delle entita' rimessi al loro tag. Cifre e
sequenze esadecimali vengono normalizzate perche' nella modalita' predefinita i
valori cyber non sono entita': senza, un IP diverso a ogni riga farebbe sembrare
unica una struttura identica — cioe' il cap non caccerebbe mai niente.

    python -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import generate_cyber_pii as cy  # noqa: E402


def rec(text, entities=()):
    return {"source_text": text,
            "entities": [{"value": v, "label": lab,
                          "start": text.index(v), "end": text.index(v) + len(v)}
                         for v, lab in entities]}


class TestSkeleton(unittest.TestCase):

    def test_the_same_structure_with_different_values_is_one_skeleton(self):
        a = rec("Il server di Mario Rossi risponde.", [("Mario Rossi", "FULLNAME")])
        b = rec("Il server di Anna Bianchi risponde.", [("Anna Bianchi", "FULLNAME")])
        self.assertEqual(cy.skeleton(a), cy.skeleton(b))

    def test_a_different_structure_is_a_different_skeleton(self):
        a = rec("Il server di Mario Rossi risponde.", [("Mario Rossi", "FULLNAME")])
        b = rec("Ha scritto Mario Rossi in data odierna.", [("Mario Rossi", "FULLNAME")])
        self.assertNotEqual(cy.skeleton(a), cy.skeleton(b))

    def test_unlabelled_cyber_values_do_not_fake_diversity(self):
        # e' il caso della modalita' predefinita: gli IP non sono entita'
        a = rec("Connessione da 203.0.113.5 sulla porta 443.")
        b = rec("Connessione da 198.51.100.9 sulla porta 8080.")
        self.assertEqual(cy.skeleton(a), cy.skeleton(b))

    def test_hashes_are_normalised_too(self):
        a = rec("Artefatto con hash d41d8cd98f00b204e9800998ecf8427e trovato.")
        b = rec("Artefatto con hash 5f4dcc3b5aa765d61d8327deb882cf99 trovato.")
        self.assertEqual(cy.skeleton(a), cy.skeleton(b))

    def test_word_like_cyber_values_are_masked_too(self):
        # domini, percorsi e utenze sono fatti di PAROLE: normalizzare cifre ed
        # esadecimali non basta, e senza i detector il cap non morde
        for x, y in (("Traffico verso evil.example bloccato.",
                      "Traffico verso login-verify.test bloccato."),
                     ("Artefatto in C:\\Users\\m.rossi\\Temp rilevato.",
                      "Artefatto in C:\\Users\\a.bianchi\\backup rilevato."),
                     ("Scaricato da https://a.example/x.bin ieri.",
                      "Scaricato da https://b.test/y.zip ieri.")):
            self.assertEqual(cy.skeleton(rec(x)), cy.skeleton(rec(y)), x)

    def test_the_skeleton_is_the_same_in_both_labelling_modes(self):
        # con --label-cyber l'IP e' un'entita', senza non lo e': la struttura no
        text = "Connessione da 203.0.113.5 verso evil.example."
        etichettato = rec(text, [("203.0.113.5", "IP"), ("evil.example", "DOMAIN")])
        nudo = rec(text)
        self.assertEqual(cy.skeleton(etichettato), cy.skeleton(nudo))

    def test_different_prose_is_not_collapsed(self):
        a = rec("Connessione da 203.0.113.5 sulla porta 443.")
        b = rec("Blocco della connessione da 203.0.113.5 sulla porta 443.")
        self.assertNotEqual(cy.skeleton(a), cy.skeleton(b))


class TestDedupe(unittest.TestCase):

    def test_exact_duplicates_are_removed(self):
        rows = [rec("stessa riga identica"), rec("stessa riga identica"),
                rec("un'altra riga")]
        out, stat = cy.dedupe(rows, cap=0)
        self.assertEqual(len(out), 2)
        self.assertEqual(stat["duplicati_esatti"], 1)

    def test_the_cap_limits_rows_per_skeleton(self):
        rows = [rec(f"Connessione da 203.0.113.{i} sulla porta 443.") for i in range(1, 51)]
        out, stat = cy.dedupe(rows, cap=20)
        self.assertEqual(len(out), 20)
        self.assertEqual(stat["oltre_il_cap"], 30)
        self.assertEqual(stat["scheletri"], 1)

    def test_the_cap_is_per_skeleton_not_global(self):
        a = [rec(f"Connessione da 203.0.113.{i} sulla porta 443.") for i in range(1, 31)]
        b = [rec(f"Blocco applicato su 198.51.100.{i} verso 443.") for i in range(1, 31)]
        out, stat = cy.dedupe(a + b, cap=20)
        self.assertEqual(len(out), 40)          # 20 per ciascuno dei due scheletri
        self.assertEqual(stat["scheletri"], 2)

    def test_cap_zero_disables_the_cap_but_not_exact_dedup(self):
        rows = [rec(f"Connessione da 203.0.113.{i} sulla porta 443.") for i in range(1, 31)]
        rows.append(rows[0])
        out, stat = cy.dedupe(rows, cap=0)
        self.assertEqual(len(out), 30)
        self.assertEqual(stat["duplicati_esatti"], 1)
        self.assertEqual(stat["oltre_il_cap"], 0)

    def test_the_order_of_the_kept_rows_is_preserved(self):
        rows = [rec(f"riga numero {i} distinta") for i in range(5)]
        out, _ = cy.dedupe(rows, cap=0)
        self.assertEqual([r["source_text"] for r in out],
                         [r["source_text"] for r in rows])


if __name__ == "__main__":
    unittest.main()
