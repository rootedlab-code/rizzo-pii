# -*- coding: utf-8 -*-
"""
Test dell'adattatore verso i provider OpenAI-compatible
(src/data_pipeline/generate_cyber_pii.py).

Girano contro un server HTTP FINTO nel processo di test: nessun modello caricato,
nessuna rete verso l'esterno, nessuna quota consumata, nessun carico sulla
macchina. E' anche il test migliore, perche' permette di provare le risposte
malformate e gli errori, che con un provider vero non si sanno riprodurre.

    python -m unittest discover -s tests
"""

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import generate_cyber_pii as cy  # noqa: E402

# Cosa il server finto deve rispondere alla prossima richiesta, e cosa ha ricevuto.
NEXT = {"status": 200, "body": None}
SEEN = {}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        SEEN["path"] = self.path
        SEEN["auth"] = self.headers.get("Authorization")
        SEEN["body"] = json.loads(self.rfile.read(length) or b"{}")
        payload = json.dumps(NEXT["body"]).encode()
        self.send_response(NEXT["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass                      # niente rumore nell'output dei test


def _reply(text):
    return {"choices": [{"message": {"content": text}}]}


class ProviderTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/v1"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        NEXT.update(status=200, body=_reply("testo"))
        SEEN.clear()

    def call(self, **kw):
        return cy.openai_compat_call("prompt di prova", self.base, "modello-finto", **kw)


class TestRequestShape(ProviderTestCase):

    def test_it_posts_to_the_chat_completions_path(self):
        self.call()
        self.assertEqual(SEEN["path"], "/v1/chat/completions")

    def test_the_prompt_travels_as_a_user_message(self):
        self.call()
        self.assertEqual(SEEN["body"]["messages"],
                         [{"role": "user", "content": "prompt di prova"}])
        self.assertEqual(SEEN["body"]["model"], "modello-finto")

    def test_no_authorization_header_without_a_key(self):
        # endpoint locale: mandare un Bearer vuoto fa rifiutare la richiesta ad alcuni
        self.call()
        self.assertIsNone(SEEN["auth"])

    def test_the_key_travels_as_a_bearer_token(self):
        self.call(api_key="segreto")
        self.assertEqual(SEEN["auth"], "Bearer segreto")

    def test_a_trailing_slash_in_the_base_url_does_not_double_up(self):
        cy.openai_compat_call("p", self.base + "/", "m")
        self.assertEqual(SEEN["path"], "/v1/chat/completions")


class TestResponseHandling(ProviderTestCase):

    def test_it_returns_the_message_content(self):
        NEXT["body"] = _reply("Il {DATE} l'analista {FULLNAME} ha isolato {HOSTNAME}.")
        self.assertEqual(self.call(),
                         "Il {DATE} l'analista {FULLNAME} ha isolato {HOSTNAME}.")

    def test_reasoning_blocks_are_stripped(self):
        # i modelli locali con ragionamento esplicito antepongono <think>...</think>,
        # che altrimenti finirebbe dentro il template
        NEXT["body"] = _reply("<think>rifletto un attimo</think>\nTesto {DATE} utile.")
        self.assertEqual(self.call(), "Testo {DATE} utile.")

    def test_a_multiline_reasoning_block_is_stripped_too(self):
        NEXT["body"] = _reply("<think>\nprima riga\nseconda riga\n</think>  {ORG} ok")
        self.assertEqual(self.call(), "{ORG} ok")

    def test_an_empty_answer_becomes_none(self):
        NEXT["body"] = _reply("   ")
        self.assertIsNone(self.call())

    def test_an_answer_of_only_reasoning_becomes_none(self):
        NEXT["body"] = _reply("<think>nient'altro</think>")
        self.assertIsNone(self.call())


class TestFailures(ProviderTestCase):
    """Un provider che sbaglia non deve far esplodere la generazione: None e si va
    avanti, cosi' il conteggio 'senza risposta' resta leggibile."""

    def test_an_http_error_gives_none(self):
        NEXT.update(status=429, body={"error": {"message": "quota"}})
        self.assertIsNone(self.call())

    def test_a_response_without_choices_gives_none(self):
        NEXT["body"] = {"error": "qualcosa"}
        self.assertIsNone(self.call())

    def test_a_malformed_choice_gives_none(self):
        NEXT["body"] = {"choices": [{}]}
        self.assertIsNone(self.call())

    def test_an_unreachable_endpoint_gives_none(self):
        self.assertIsNone(cy.openai_compat_call("p", "http://127.0.0.1:1/v1", "m",
                                                timeout=2))


class TestCallerSelection(ProviderTestCase):

    def test_openai_provider_without_a_model_is_refused(self):
        import os
        saved = os.environ.pop("PII_LLM_MODEL", None)
        try:
            self.assertIsNone(cy.make_caller("openai", self.base, None))
        finally:
            if saved is not None:
                os.environ["PII_LLM_MODEL"] = saved

    def test_the_caller_reaches_the_configured_endpoint(self):
        NEXT["body"] = _reply("risposta")
        call = cy.make_caller("openai", self.base, "modello-finto")
        self.assertEqual(call("ciao"), "risposta")
        self.assertEqual(SEEN["body"]["messages"][0]["content"], "ciao")

    def test_llm_templates_stops_after_repeated_failures(self):
        NEXT.update(status=500, body={"error": "boom"})
        call = cy.make_caller("openai", self.base, "modello-finto")
        self.assertEqual(cy.llm_templates(3, call, "finto"), [])

    def test_llm_templates_without_a_caller_returns_nothing(self):
        self.assertEqual(cy.llm_templates(2, None), [])


if __name__ == "__main__":
    unittest.main()
