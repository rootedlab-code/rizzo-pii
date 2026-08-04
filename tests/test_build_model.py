# -*- coding: utf-8 -*-
"""
Test sul modello che finisce nel pacchetto (build.spec, build_sidecar.spec, build_*.sh).

Lo stesso path era scritto a mano in QUATTRO file, tenuti allineati da un commento
("deve combaciare con build_sidecar.spec"). Nessun test lo sorvegliava, e infatti
puntavano tutti a `models/rizzo-pii-0.3B-v1.2.0`, che non esiste piu' in questa repo:
il build era gia' rotto, e nessuno poteva accorgersene senza lanciarlo.

Questi test non sanno costruire un pacchetto — sarebbero minuti e 1,8 GB. Guardano la
proprieta' che rende il difetto impossibile: **una sola sorgente di verita'**.

    python -m unittest discover -s tests
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SPEC = ("build.spec", "build_sidecar.spec")
SHELL = ("build_linux.sh", "build_mac.sh")
VARIABILE = "PII_BUILD_MODEL"


def _leggi(nome):
    return (ROOT / nome).read_text("utf-8")


class TestSorgenteUnica(unittest.TestCase):

    def test_both_specs_take_the_model_from_the_same_variable(self):
        for nome in SPEC:
            with self.subTest(file=nome):
                self.assertIn(VARIABILE, _leggi(nome))

    def test_the_shell_builders_export_the_variable_instead_of_a_second_path(self):
        # esportarla e' cio' che la fa arrivare a pyinstaller, che lancia lo spec in un
        # processo figlio: senza export lo spec userebbe il proprio default e i due
        # potrebbero divergere senza che nessuno se ne accorga
        for nome in SHELL:
            with self.subTest(file=nome):
                self.assertRegex(_leggi(nome), rf"export\s+{VARIABILE}=")

    def test_no_build_file_hardcodes_a_model_path_any_more(self):
        # la regressione precisa: quattro copie di "models/rizzo-pii-0.3B-v1.2.0"
        percorso = re.compile(r'["\']models/rizzo-pii-0\.3B[^"\']*["\']')
        for nome in SPEC + SHELL:
            with self.subTest(file=nome):
                testo = _leggi(nome)
                trovati = [m for m in percorso.findall(testo)
                           if VARIABILE not in testo[max(0, testo.find(m) - 60):testo.find(m)]]
                self.assertEqual(trovati, [], f"path del modello scritto a mano in {nome}")


class TestModelloPredefinito(unittest.TestCase):

    def test_the_default_packaged_model_is_the_one_the_criterion_accepted(self):
        """Il default non e' una preferenza: e' l'esito di docs/CRITERIO.md.

        Il checkpoint di sicurezza ha superato il criterio depositato prima della
        misura (riserva: recall 0.737 -> 0.808, regole A/B/C, zero tag in regressione)
        e migliora anche sul dominio legale. Spedire quello di partenza significherebbe
        aver speso l'ultimo campione cieco per un risultato che nessun utente riceve.
        """
        for nome in SPEC:
            with self.subTest(file=nome):
                self.assertIn("models/rizzo-pii-0.3B-security", _leggi(nome))

    def test_the_specs_refuse_a_model_directory_without_a_config(self):
        # un path sbagliato deve fermare il build subito, non produrre un pacchetto da
        # 1,8 GB con dentro una cartella vuota
        for nome in SPEC:
            with self.subTest(file=nome):
                self.assertIn("config.json", _leggi(nome))


if __name__ == "__main__":
    unittest.main()
