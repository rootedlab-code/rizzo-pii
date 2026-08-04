# -*- coding: utf-8 -*-
"""
Test della pagina servita da app.py (l'HTML/JS vive in una stringa dentro il modulo).

La suite non puo' eseguire quel JavaScript, ma tre cose si affermano lo stesso, e sono
quelle che si rompono in silenzio:

  1. i controlli esistono davvero nella pagina — un `getElementById` su un id assente
     non solleva niente, restituisce null e il pannello smette di funzionare a meta';
  2. ogni chiave di traduzione usata e' definita in ENTRAMBE le lingue — una chiave
     presente solo in italiano stampa "undefined" all'utente inglese, e nessun test
     del server se ne accorgerebbe;
  3. il salvataggio invia i detector PRIMA della policy — al contrario il server
     rifiuta con 400 un tag che l'utente vede scritto nel proprio campo.

    python -m unittest discover -s tests
"""

import re
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "app"))


def _install_stubs():
    torch = types.ModuleType("torch")
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    sys.modules.setdefault("torch", torch)
    transformers = types.ModuleType("transformers")

    class _FakeNlp:
        model = types.SimpleNamespace(config=types.SimpleNamespace(label2id={}))

        def __call__(self, texts, *a, **k):
            return [[] for _ in texts] if isinstance(texts, list) else []

    transformers.pipeline = lambda *a, **k: _FakeNlp()
    sys.modules.setdefault("transformers", transformers)
    fitz = types.ModuleType("fitz")
    fitz.open = lambda *a, **k: None
    sys.modules.setdefault("fitz", fitz)


_install_stubs()

import app     # noqa: E402


class UITestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = app.app.test_client().get("/").data.decode("utf-8")


class TestControlli(UITestCase):

    def test_the_detector_switch_is_on_the_page(self):
        # senza, il pacchetto cyber resta irraggiungibile per chi usa l'app: era
        # accendibile solo da una variabile d'ambiente che Tauri non passa
        self.assertIn('id="cfgPackCyber"', self.html)

    def test_the_profile_warning_area_is_on_the_page(self):
        self.assertIn('id="cfgProfileNote"', self.html)

    def test_there_is_an_amber_style_that_is_not_an_error(self):
        # un profilo che non puo' mantenere la promessa non e' un fallimento: usare
        # il rosso direbbe all'utente che qualcosa e' andato storto, e non e' vero
        self.assertIn(".cfg-status.warn", self.html)


class TestTraduzioni(UITestCase):

    def blocchi(self):
        i_it, i_en = self.html.find(" it:{"), self.html.find("\n en:{")
        return self.html[i_it:i_en], self.html[i_en:self.html.find("\n};", i_en)]

    def chiavi_usate(self):
        return (set(re.findall(r"tt\('([a-z_0-9]+)'\)", self.html))
                | set(re.findall(r'data-i18n="([a-z_0-9]+)"', self.html)))

    def test_every_key_used_is_defined_in_both_languages(self):
        it, en = self.blocchi()
        self.assertTrue(self.chiavi_usate(), "nessuna chiave trovata: regex da rivedere")
        for chiave in sorted(self.chiavi_usate()):
            with self.subTest(chiave=chiave):
                self.assertRegex(it, rf"[\s{{,]{chiave}:")
                self.assertRegex(en, rf"[\s{{,]{chiave}:")


class TestOrdineDelSalvataggio(UITestCase):

    def test_saving_posts_the_detectors_before_the_policy(self):
        """L'ordine sul filo deve rispecchiare quello del server.

        `known_tags()` legge i detector attivi: inviando prima la policy, un
        `keep_tags: IP` verrebbe rifiutato con 400 perche' il pacchetto non e' ancora
        acceso — su un valore che l'utente ha davanti agli occhi."""
        salva = self.html[self.html.find("async function saveConfig"):]
        salva = salva[:salva.find("\n}")]

        self.assertLess(salva.find("'/detectors'"), salva.find("'/policy'"))

    def test_saving_reports_the_tags_that_went_back_to_masked(self):
        # spegnendo un pacchetto quei tag escono dalla tassonomia: e' l'unica cosa che
        # l'interfaccia non puo' dedurre da sola
        self.assertIn("cfg_tags_dropped", self.html)


if __name__ == "__main__":
    unittest.main()
