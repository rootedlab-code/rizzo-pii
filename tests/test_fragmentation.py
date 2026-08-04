# -*- coding: utf-8 -*-
"""
Test della misura di frammentazione (src/training/fragmentation.py).

La misura esiste per sostituire un numero pubblicato a mano. Perche' abbia senso
sostituirlo, tre cose devono valere e sono quelle provate qui:

  1. cio' che il prodotto fonde viene contato come frammentazione, e cio' che il
     prodotto NON fonde no — in particolare gli span validati, che restano distinti
     perche' due IP accanto sono due indirizzi, non un indirizzo lungo;
  2. la misura vede lo stesso sistema di `combined_entities()`: se le due divergono
     siamo daccapo al gemello #2, con la misura che risponde al posto dell'app;
  3. se le predizioni non parlano dello stesso testo del gold, la misura si ferma
     invece di stampare numeri — e' la guardia che mancava in GEMELLI #23.

    python -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "training"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import evaluate_entities as ev     # noqa: E402
import fragmentation as fr         # noqa: E402

E = ev.Entity


class PacchettiTestCase(unittest.TestCase):
    """`enable_packs` e' stato di modulo: si riporta al core dopo ogni test."""

    def tearDown(self):
        ev._load_app().enable_packs([])


class TestConteggio(PacchettiTestCase):

    def test_due_span_adiacenti_dello_stesso_tag_contano_come_una_spezzata(self):
        # e' il caso della scheda: 'Giulia Moretti' esce come due FULLNAME e l'utente
        # si ritrova [FULLNAME_1] [FULLNAME_2], cioe' due persone per l'LLM a valle
        testo = "Giulia Moretti ha isolato l host colpito ."
        modello = {E(0, 6, "FULLNAME"), E(7, 14, "FULLNAME")}

        pre, post = fr.spans_pre_post(testo, modello, packs=())
        stat = fr.tally(pre, post)

        self.assertEqual(stat["FULLNAME"]["emessi"], 2)
        self.assertEqual(stat["FULLNAME"]["finali"], 1)
        self.assertEqual(stat["FULLNAME"]["spezzate"], 1)

    def test_due_entita_distinte_non_sono_una_frammentazione(self):
        # separate da ' e ': non sono adiacenti, quindi il prodotto non le fonde e
        # contarle come spezzate gonfierebbe la misura proprio sui testi con elenchi
        testo = "Giulia Moretti e Marco Bini erano di turno ."
        modello = {E(0, 14, "FULLNAME"), E(17, 27, "FULLNAME")}

        pre, post = fr.spans_pre_post(testo, modello, packs=())
        stat = fr.tally(pre, post)

        self.assertEqual(stat["FULLNAME"]["finali"], 2)
        self.assertEqual(stat["FULLNAME"]["spezzate"], 0)

    def test_gli_span_validati_adiacenti_restano_due_entita(self):
        # 203.0.113.1 203.0.113.2 sono due indirizzi: fonderli li mascherebbe con un
        # solo segnaposto, e il documento anonimizzato direbbe una cosa falsa
        testo = "Gli host 203.0.113.1 203.0.113.2 rispondono ancora ."

        pre, post = fr.spans_pre_post(testo, set(), packs=("cyber",))
        stat = fr.tally(pre, post)

        self.assertEqual(stat["IP"]["emessi"], 2)
        self.assertEqual(stat["IP"]["finali"], 2)
        self.assertEqual(stat["IP"]["spezzate"], 0)


class TestGemelloConLaValutazione(PacchettiTestCase):

    def test_le_entita_finali_coincidono_con_combined_entities(self):
        # se questa cade, la misura sta descrivendo un sistema che non e' quello
        # valutato altrove, ed e' esattamente il difetto che ha prodotto
        # 'FULLNAME migliora' mentre il prodotto peggiorava
        testo = "Giulia Moretti ha isolato 203.0.113.1 alle 08:00 ."
        modello = {E(0, 6, "FULLNAME"), E(7, 14, "FULLNAME")}

        _pre, post = fr.spans_pre_post(testo, modello, packs=("cyber",))
        mie = {E(e["start"], e["end"], e["label"]) for e in post}
        sue = ev.combined_entities(testo, modello, packs=("cyber",))

        self.assertEqual(mie, sue)


class TestGuardie(PacchettiTestCase):

    def test_si_ferma_se_il_testo_del_gold_e_quello_delle_predizioni_divergono(self):
        gold = [{"source_text": "Il CAP e' 20121 .", "entities": []}]
        pred = [{"source_text": "Il CA ##P e' 20121 .", "entities": []}]

        with self.assertRaises(SystemExit):
            fr.measure(gold, pred, packs=())

    def test_si_ferma_se_i_due_file_hanno_un_numero_di_righe_diverso(self):
        gold = [{"source_text": "a", "entities": []},
                {"source_text": "b", "entities": []}]
        pred = [{"source_text": "a", "entities": []}]

        with self.assertRaises(SystemExit):
            fr.measure(gold, pred, packs=())

    def test_un_tag_senza_entita_dice_N_V_e_non_zero(self):
        # 0,0% e' un'affermazione ('non frammenta mai'), N/V e' l'assenza di
        # un'affermazione: confonderle e' come far dire OK a un controllo che non ha
        # verificato niente
        self.assertEqual(fr._quota(0, 0), "N/V")
        self.assertEqual(fr._quota(0, 10), "0.0%")


if __name__ == "__main__":
    unittest.main()
