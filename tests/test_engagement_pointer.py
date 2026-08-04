# -*- coding: utf-8 -*-
"""
Test del puntatore all'ingaggio (engagement.json) e della catena di scope.py.

Il file di scope dice DI CHI e' ogni valore — gli IP del cliente, gli indicatori
dell'avversario — e sta fuori dalla repo, uno per ingaggio. L'app desktop non aveva
modo di ricordare quale fosse: `PII_SCOPE_FILE` non viene passata al sidecar.

Il puntatore risolve quel problema **senza toccare il vincolo che conta**: contiene un
percorso, mai dei valori, e dal lato Python si legge soltanto. Questi test provano
entrambe le cose, inclusa l'ultima — che nel modulo non esista proprio nulla che scriva
quel file.

    python -m unittest discover -s tests
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "app"))

import scope           # noqa: E402
import server_config   # noqa: E402


class PuntatoreTestCase(unittest.TestCase):
    """Config dir temporanea e nessuna env ereditata: i test non leggono la
    configurazione di chi li lancia (e' il difetto D10, gia' costato due test rossi)."""

    def setUp(self):
        self._env = {k: os.environ.pop(k) for k in (scope.ENV_SCOPE_FILE,)
                     if k in os.environ}
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._orig = server_config.config_dir
        server_config.config_dir = lambda: self.tmp

    def tearDown(self):
        server_config.config_dir = self._orig
        self._tmp.cleanup()
        os.environ.pop(scope.ENV_SCOPE_FILE, None)
        os.environ.update(self._env)

    def scrivi_puntatore(self, contenuto):
        p = self.tmp / server_config.ENGAGEMENT_FILENAME
        p.write_text(contenuto if isinstance(contenuto, str)
                     else json.dumps(contenuto), "utf-8")
        return p


class TestCatena(PuntatoreTestCase):

    def test_nothing_configured_means_no_scope(self):
        self.assertIsNone(scope.scope_path())

    def test_the_pointer_is_used_when_nothing_else_is_set(self):
        self.scrivi_puntatore({"scope_file": "/ingaggi/acme/scope.json"})

        self.assertEqual(scope.scope_path(), Path("/ingaggi/acme/scope.json"))

    def test_the_environment_beats_the_pointer(self):
        self.scrivi_puntatore({"scope_file": "/ingaggi/vecchio/scope.json"})
        os.environ[scope.ENV_SCOPE_FILE] = "/ingaggi/nuovo/scope.json"

        self.assertEqual(scope.scope_path(), Path("/ingaggi/nuovo/scope.json"))

    def test_the_cli_beats_everything(self):
        self.scrivi_puntatore({"scope_file": "/ingaggi/dal-file/scope.json"})
        os.environ[scope.ENV_SCOPE_FILE] = "/ingaggi/da-env/scope.json"

        self.assertEqual(scope.scope_path("/ingaggi/da-cli/scope.json"),
                         Path("/ingaggi/da-cli/scope.json"))

    def test_the_home_shorthand_is_expanded(self):
        self.scrivi_puntatore({"scope_file": "~/ingaggi/acme/scope.json"})

        self.assertEqual(scope.scope_path(), Path.home() / "ingaggi/acme/scope.json")


class TestPuntatoreMalformato(PuntatoreTestCase):

    def test_a_corrupt_pointer_means_no_scope_rather_than_a_crash(self):
        self.scrivi_puntatore("{non json")

        self.assertIsNone(scope.scope_path())

    def test_a_pointer_that_is_not_an_object_means_no_scope(self):
        self.scrivi_puntatore("[1, 2]")

        self.assertIsNone(scope.scope_path())

    def test_a_pointer_without_the_key_means_no_scope(self):
        self.scrivi_puntatore({"altro": "valore"})

        self.assertIsNone(scope.scope_path())

    def test_an_empty_path_is_treated_as_absent(self):
        self.scrivi_puntatore({"scope_file": ""})

        self.assertIsNone(scope.scope_path())


class TestIlPuntatoreNonEsceDalLatoPython(PuntatoreTestCase):
    """Il vincolo che regge tutto il progetto dello scope."""

    def test_only_the_path_is_read_never_any_value(self):
        # se un giorno qualcuno mettesse i valori dentro il puntatore invece del
        # percorso, questo test non se ne accorgerebbe - ma scope_path ritorna un
        # percorso, quindi qualunque altra chiave viene semplicemente ignorata
        self.scrivi_puntatore({"scope_file": "/x/scope.json",
                               "own": {"IP": ["203.0.113.1"]}})

        self.assertEqual(scope.scope_path(), Path("/x/scope.json"))

    def test_nothing_in_the_python_side_writes_the_pointer(self):
        """Il percorso entra, ma non dalla webview.

        Un POST che accetta un percorso renderebbe l'endpoint un oracolo di lettura del
        filesystem, e i messaggi di ScopeError citano un valore preso dal file. Lo
        scrive il dialogo nativo del sistema operativo, dal lato Rust."""
        sorgenti = [(ROOT / "src" / "app" / f).read_text("utf-8")
                    for f in ("scope.py", "server_config.py", "app.py")]

        for nome, testo in zip(("scope.py", "server_config.py", "app.py"), sorgenti):
            with self.subTest(file=nome):
                self.assertNotIn(server_config.ENGAGEMENT_FILENAME + '"', testo.replace(
                    'ENGAGEMENT_FILENAME = "engagement.json"', ""))
                # nessuna scrittura del puntatore, in nessuna forma
                self.assertNotIn("engagement_path().write", testo)


class TestEntryPointDelSidecar(unittest.TestCase):
    """serve.py: cosa promette la docstring e cosa fa il codice.

    La stesura precedente dichiarava argomenti `--host/--port` che non ha mai letto, e
    annunciava un percorso di log che su Linux e macOS non esiste. Un file che descrive
    la catena di un altro modulo invece del proprio comportamento e' un difetto di
    documentazione con conseguenze pratiche: chi cerca il log non lo trova."""

    def setUp(self):
        self.sorgente = (ROOT / "src" / "app" / "serve.py").read_text("utf-8")

    def test_it_does_not_promise_command_line_arguments(self):
        # non ha argparse, e Tauri non passa mai argv (lib.rs, spawn_sidecar)
        self.assertNotIn("argparse", self.sorgente)
        self.assertNotIn("--host / --port", self.sorgente)

    def test_the_log_goes_where_the_configuration_lives(self):
        # prima usava LOCALAPPDATA anche fuori da Windows, dove non esiste: il log
        # finiva in ~/rizzo-pii/ mentre docstring e messaggi ne annunciavano un'altra
        self.assertIn("config_dir()", self.sorgente)
        self.assertNotIn('os.environ.get("LOCALAPPDATA"', self.sorgente)

    def test_the_engagement_is_checked_before_the_model_is_loaded(self):
        """Il pre-check costa millisecondi, l'import di app carica 1,2 GB.

        Senza, chi ha un file di ingaggio rotto aspetta il caricamento completo per
        sentirsi dire che un JSON e' malformato. Misurato: 0,026 s contro decine di
        secondi."""
        self.assertLess(self.sorgente.find("scope_mod.load_scope()"),
                        self.sorgente.find("from app import app"))

    def test_a_broken_engagement_exits_with_the_configuration_code(self):
        # 78 e non 1: Tauri traduce qualunque codice diverso da 76 in "il backend si e'
        # chiuso inaspettatamente", che non dice quale file rileggere
        self.assertIn("EXIT_BAD_CONFIG", self.sorgente)


if __name__ == "__main__":
    unittest.main()
