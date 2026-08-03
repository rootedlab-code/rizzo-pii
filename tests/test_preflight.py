# -*- coding: utf-8 -*-
"""
Test del preflight (src/training/preflight.py).

Il preflight e' la cosa che gira PRIMA di spendere ore di GPU, quindi e' anche
l'unica il cui difetto costa quanto la corsa che avrebbe dovuto proteggere. Il modo
in cui si guasta non e' fallire a sproposito: e' passare quando non ha potuto
verificare nulla — un file assente, una libreria mancante — e diventare esattamente
il difetto che esisteva per prevenire.

I test qui sorvegliano due cose:

  - l'impronta del test congelato, che si esegue una volta sola e decide la
    sostituzione del modello in produzione (docs/CRITERIO.md);
  - la distinzione fra OK, FALLITO e NON VERIFICATO, che e' il cuore dello script.

    python -m unittest discover -s tests
"""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "training"))

import preflight as pf     # noqa: E402

CONTENUTO = b'{"tokens": ["Mario", "Rossi"], "bio_labels": ["B-GIVENNAME", "B-SURNAME"]}\n'


class TestFrozenFingerprint(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.base = Path(self.dir.name)
        self.dato = self.base / "test_congelato_legale.jsonl"
        self.sha = self.base / "test_congelato.sha256"
        self.dato.write_bytes(CONTENUTO)
        self.sha.write_text(hashlib.sha256(CONTENUTO).hexdigest())

    def tearDown(self):
        self.dir.cleanup()

    def test_an_untouched_file_passes(self):
        ok, verificabile, _ = pf.verifica_impronta(self.dato, self.sha)
        self.assertTrue(ok)
        self.assertTrue(verificabile)

    def test_a_single_changed_byte_fails(self):
        self.dato.write_bytes(CONTENUTO.replace(b"Mario", b"Marco"))
        ok, verificabile, dettaglio = pf.verifica_impronta(self.dato, self.sha)
        self.assertFalse(ok)
        self.assertTrue(verificabile)      # verificato, e il verdetto e' "diverso"
        self.assertIn("IMPRONTA DIVERSA", dettaglio)

    def test_appending_a_row_fails(self):
        # il caso realistico: si rigenera il file e viene piu' lungo di prima
        with open(self.dato, "ab") as f:
            f.write(CONTENUTO)
        ok, _, _ = pf.verifica_impronta(self.dato, self.sha)
        self.assertFalse(ok)

    def test_a_missing_file_is_not_verified_rather_than_ok(self):
        self.dato.unlink()
        ok, verificabile, dettaglio = pf.verifica_impronta(self.dato, self.sha)
        self.assertFalse(ok)
        self.assertFalse(verificabile)
        self.assertIn("assente", dettaglio)

    def test_a_missing_fingerprint_is_not_verified_rather_than_ok(self):
        # senza questa distinzione basterebbe cancellare il .sha256 per far "passare"
        # il controllo, che e' il modo piu' silenzioso di perdere il test congelato
        self.sha.unlink()
        ok, verificabile, dettaglio = pf.verifica_impronta(self.dato, self.sha)
        self.assertFalse(ok)
        self.assertFalse(verificabile)
        self.assertIn("nessuna impronta", dettaglio)

    def test_the_fingerprint_file_may_carry_a_filename_beside_the_hash(self):
        # `sha256sum file > file.sha256` scrive "<hash>  <nome>": si accetta comunque
        self.sha.write_text(f"{hashlib.sha256(CONTENUTO).hexdigest()}  {self.dato.name}\n")
        ok, _, _ = pf.verifica_impronta(self.dato, self.sha)
        self.assertTrue(ok)


class TestCheckOutcomes(unittest.TestCase):
    """OK, FALLITO e N/V sono tre esiti distinti. Collassare gli ultimi due e'
    precisamente il difetto che questo script esiste per non avere."""

    def setUp(self):
        pf.ESITI.clear()

    def tearDown(self):
        pf.ESITI.clear()

    def test_a_passing_check_is_ok(self):
        pf.check("qualcosa", True, "dettaglio")
        self.assertEqual(pf.ESITI[0][1].strip(), "OK")

    def test_a_failing_check_is_reported_as_failed(self):
        pf.check("qualcosa", False)
        self.assertEqual(pf.ESITI[0][1].strip(), "FALLITO")

    def test_an_unverifiable_check_is_never_reported_as_ok(self):
        for esito in (True, False):
            pf.ESITI.clear()
            pf.check("qualcosa", esito, verificabile=False)
            self.assertEqual(pf.ESITI[0][1].strip(), "N/V")

    def test_check_returns_the_verdict_so_the_caller_can_stop(self):
        # il controllo "i file esistono" interrompe il preflight sul proprio esito:
        # se check() non lo restituisse, proseguirebbe su file inesistenti
        self.assertTrue(pf.check("a", True))
        self.assertFalse(pf.check("b", False))


class TestParserDefaults(unittest.TestCase):

    def test_the_frozen_test_is_checked_without_being_asked_for(self):
        # se l'impronta del test congelato fosse dietro un'opzione da ricordare,
        # verrebbe verificata solo quando qualcuno gia' sospetta qualcosa
        args = pf.build_parser().parse_args(["--train", "t.jsonl", "--eval", "e.jsonl"])
        self.assertTrue(args.frozen.endswith("test_congelato_legale.jsonl"))
        self.assertTrue(args.frozen_sha.endswith("test_congelato.sha256"))


if __name__ == "__main__":
    unittest.main()
