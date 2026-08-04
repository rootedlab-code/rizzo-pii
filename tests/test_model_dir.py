# -*- coding: utf-8 -*-
"""
Test della risoluzione del checkpoint da caricare (src/app/server_config.py).

Esiste per un difetto che nessun test poteva vedere, perche' la regola viveva dentro
un `if` a livello di modulo in app.py, eseguito all'import: dentro l'eseguibile
`sys._MEIPASS` c'e' sempre, quindi il ramo PII_MODEL_DIR era **codice morto** e
l'unico modo di cambiare modello era ricompilare. Estratta la regola in una funzione
pura, la precedenza diventa una cosa che si puo' affermare.

    python -m unittest discover -s tests
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "app"))

import server_config as sc     # noqa: E402


def _fai_checkpoint(base, nome):
    """Un checkpoint minimo: una directory con dentro config.json."""
    d = Path(base) / nome
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text("{}", "utf-8")
    return d


class ModelDirTestCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.models = self.tmp / "models"
        self.models.mkdir()
        self.avvisi = []

    def tearDown(self):
        self._tmp.cleanup()

    def risolvi(self, **kw):
        kw.setdefault("models_root", self.models)
        kw.setdefault("warn", self.avvisi.append)
        return sc.resolve_model_dir(**kw)


class TestPrecedenza(ModelDirTestCase):

    def test_an_explicit_override_wins_even_over_the_bundled_model(self):
        # e' LA correzione: prima il ramo del pacchetto veniva per primo e vinceva
        # sempre, quindi dentro l'app impacchettata la variabile non serviva a nulla
        altro = _fai_checkpoint(self.tmp, "altro-checkpoint")

        scelto = self.risolvi(override=str(altro), bundled=str(self.tmp / "pii_model"))

        self.assertEqual(scelto, str(altro))
        self.assertEqual(self.avvisi, [])

    def test_the_bundled_model_wins_over_the_development_tree(self):
        # senza override, dentro il pacchetto si usa cio' che e' stato impacchettato:
        # l'albero models/ della macchina di sviluppo li' non esiste nemmeno
        _fai_checkpoint(self.models, "rizzo-pii-0.3B-v9.0.0")
        impacchettato = self.tmp / "pii_model"

        self.assertEqual(self.risolvi(bundled=str(impacchettato)), str(impacchettato))


class TestOverrideRotto(ModelDirTestCase):

    def test_an_override_that_does_not_exist_falls_back_instead_of_crashing(self):
        # morire qui ucciderebbe il sidecar prima che Flask apra la porta, e l'app
        # direbbe solo "il backend si e' chiuso inaspettatamente"
        impacchettato = self.tmp / "pii_model"

        scelto = self.risolvi(override=str(self.tmp / "inesistente"),
                              bundled=str(impacchettato))

        self.assertEqual(scelto, str(impacchettato))
        self.assertEqual(len(self.avvisi), 1)
        self.assertIn("inesistente", self.avvisi[0])

    def test_a_directory_without_config_json_is_not_a_checkpoint(self):
        # una cartella vuota fa fallire il caricamento secondi dopo, dentro
        # transformers, con un errore che non nomina la variabile sbagliata
        vuota = self.tmp / "vuota"
        vuota.mkdir()
        impacchettato = self.tmp / "pii_model"

        scelto = self.risolvi(override=str(vuota), bundled=str(impacchettato))

        self.assertEqual(scelto, str(impacchettato))
        self.assertEqual(len(self.avvisi), 1)


class TestAlberoDiSviluppo(ModelDirTestCase):

    def test_the_pinned_version_wins_over_a_newer_one(self):
        # il pin serve a NON seguire l'ultima arrivata: senza, mettere una v2.0.0
        # sperimentale in models/ cambierebbe il modello dell'app senza dirlo
        fissata = _fai_checkpoint(self.models, "rizzo-pii-0.3B-v1.2.0")
        _fai_checkpoint(self.models, "rizzo-pii-0.3B-v2.0.0")

        self.assertEqual(self.risolvi(pinned_version="1.2.0"), str(fissata))

    def test_the_newest_version_is_picked_by_number_and_not_by_name(self):
        # ordinare per stringa metterebbe la v10 prima della v9
        _fai_checkpoint(self.models, "rizzo-pii-0.3B-v9.0.0")
        ultima = _fai_checkpoint(self.models, "rizzo-pii-0.3B-v10.0.0")

        self.assertEqual(self.risolvi(), str(ultima))

    def test_it_falls_back_to_the_unversioned_model_when_none_is_versioned(self):
        prod = _fai_checkpoint(self.models, "rizzo-pii-0.3B")

        self.assertEqual(self.risolvi(pinned_version="1.2.0"), str(prod))

    def test_it_falls_back_to_legacy_when_there_is_no_model_at_all(self):
        # e' il caso di questa repo oggi: models/ contiene -base e -security, che non
        # combaciano con nessuna delle regole sopra
        self.assertEqual(self.risolvi(pinned_version="1.2.0"),
                         str(self.models / "pii_model_legacy"))


class TestIlGemelloConLaCLI(unittest.TestCase):
    """src/training/test_pii.py risolveva il modello per conto suo, con regole diverse.

    Non validava l'override e ordinava le versioni con una chiave sua. Le due politiche
    restano legittimamente diverse — l'app fissa una versione perche' il prodotto
    spedito dev'essere riproducibile, la CLI prende l'ultima perche' serve a provare
    cio' che si e' appena addestrato — ma la MECCANICA dev'essere una sola. Questo test
    guarda il sorgente perche' importare quel file esegue argparse e carica il modello.
    """

    def setUp(self):
        self.sorgente = (ROOT / "src" / "training" / "test_pii.py").read_text("utf-8")

    def test_the_cli_delegates_to_the_shared_resolver(self):
        self.assertIn("server_config.resolve_model_dir(", self.sorgente)

    def test_the_cli_does_not_define_a_resolver_of_its_own(self):
        self.assertNotIn("def resolve_model_dir", self.sorgente)


if __name__ == "__main__":
    unittest.main()
