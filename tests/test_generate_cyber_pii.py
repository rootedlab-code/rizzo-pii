# -*- coding: utf-8 -*-
"""
Test del generatore di documenti di sicurezza sintetici
(src/data_pipeline/generate_cyber_pii.py).

Il test che conta piu' di tutti e' TestDocumentationSpace: su decine di migliaia
di valori generati, NESSUNO deve cadere fuori dagli spazi riservati alla
documentazione. Un dataset sintetico che contenesse un indirizzo instradabile
starebbe pubblicando l'infrastruttura di qualcun altro.

Gli altri verificano che le righe siano nel formato che il progetto si aspetta e
che i valori prodotti siano riconoscibili dai nostri stessi detector — se non lo
fossero, il dataset non misurerebbe nulla.

Solo stdlib: nessun modello, nessuna rete.

    python -m unittest discover -s tests
"""

import ipaddress
import json
import tempfile
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))
sys.path.insert(0, str(ROOT / "src" / "app"))

import detectors_cyber              # noqa: E402
import generate_cyber_pii as cy     # noqa: E402
import generate_synthetic_pii as gen  # noqa: E402
import llm_template_bank as tb      # noqa: E402

SAMPLES = 400


class GeneratorTestCase(unittest.TestCase):
    """set_label_cyber e' stato di modulo: si ripristina sempre."""

    def setUp(self):
        self._orig = cy._label_cyber
        cy.set_label_cyber(False)

    def tearDown(self):
        cy.set_label_cyber(self._orig)


class TestDocumentationSpace(GeneratorTestCase):
    """L'invariante non negoziabile del modulo."""

    def test_every_generated_ipv4_is_in_a_reserved_range(self):
        for _ in range(SAMPLES * 10):
            addr = ipaddress.ip_address(cy.ip_piece()[0][0])
            self.assertTrue(any(addr in net for net in cy._ALL_DOC_NETS), addr)

    def test_every_generated_ipv6_is_in_the_documentation_prefix(self):
        net = ipaddress.ip_network(cy.DOC_NET_V6)
        for _ in range(SAMPLES):
            self.assertIn(ipaddress.ip_address(cy.ip6_piece()[0][0]), net)

    def test_every_generated_cidr_is_a_private_subnet(self):
        privates = [ipaddress.ip_network(n) for n in cy.PRIVATE_NETS_V4]
        for _ in range(SAMPLES):
            sub = ipaddress.ip_network(cy.cidr_piece()[0][0])
            self.assertTrue(any(sub.subnet_of(p) for p in privates), sub)

    def test_every_generated_domain_is_in_rfc2606_space(self):
        for piece in (cy.domain_piece, cy.bad_domain_piece):
            for _ in range(SAMPLES):
                self.assertTrue(cy._is_doc_domain(piece()[0][0]), piece()[0][0])

    def test_every_generated_url_host_is_in_rfc2606_space(self):
        for _ in range(SAMPLES):
            host = re.match(r"https?://([^/]+)", cy.url_piece()[0][0]).group(1)
            self.assertTrue(cy._is_doc_domain(host), host)

    def test_every_generated_asn_is_in_the_rfc5398_ranges(self):
        for _ in range(SAMPLES):
            num = int(cy.asn_piece()[0][0][2:])
            self.assertTrue(any(lo <= num <= hi for lo, hi in cy.DOC_ASN_RANGES), num)

    def test_every_generated_mac_uses_the_rfc7042_prefix(self):
        for _ in range(SAMPLES):
            self.assertTrue(cy.mac_piece()[0][0].startswith(cy.DOC_MAC_PREFIX))

    def test_whole_generated_documents_hold_the_invariant(self):
        rows, _, bad = cy.build(SAMPLES, cy.TEMPLATES, seed=7)
        self.assertEqual(bad, 0)
        for rec in rows:
            self.assertEqual(cy.in_documentation_space(rec["source_text"]), [])

    def test_the_checker_still_catches_a_routable_address(self):
        # una guardia che non fallisce mai non e' una guardia
        self.assertEqual(cy.in_documentation_space("il server 8.8.8.8 risponde"),
                         ["8.8.8.8"])
        self.assertEqual(cy.in_documentation_space("dominio malware.ru"), ["malware.ru"])

    def test_the_checker_does_not_cry_wolf_on_files_and_usernames(self):
        # username, nomi di file ed estensioni non sono domini
        for benign in ("m.rossi", "index.html", "files.bin", "dl.js", "C:\\Users\\a.bianchi"):
            self.assertEqual(cy.in_documentation_space(benign), [], benign)


class TestTemplates(GeneratorTestCase):

    def test_no_template_contains_an_inline_proper_name(self):
        # stessa guardia che il progetto applica ai template scritti dall'LLM
        for i, t in enumerate(cy.TEMPLATES):
            self.assertEqual(tb.find_stray_names(t), [], f"template {i}: {t[:60]}")

    def test_every_slot_used_by_a_template_exists(self):
        cy.register()
        for i, t in enumerate(cy.TEMPLATES):
            for slot in gen.SLOT_RE.findall(t):
                self.assertIn(slot, gen.SLOTS, f"template {i}: {{{slot}}}")

    def test_templates_use_no_checksum_bearing_slot(self):
        # validate_record non verifica i checksum: se un giorno un template usasse
        # {CF}/{PIVA}/{IBAN} servirebbe aggiungerlo, e questo test lo impone
        used = {s for t in cy.TEMPLATES for s in gen.SLOT_RE.findall(t)}
        self.assertEqual(used & {"CF", "PIVA", "IBAN", "CONTO"}, set())

    PII_SLOTS = {"FULLNAME", "ORG", "EMAIL", "PHONE", "DATE", "ADDRESS", "CITY", "AMOUNT"}

    def _with_pii(self):
        return [i for i, t in enumerate(cy.TEMPLATES)
                if set(gen.SLOT_RE.findall(t)) & self.PII_SLOTS]

    def test_most_templates_carry_a_labelled_pii(self):
        # e' il motivo per cui il dataset esiste: insegnare i tag che le regex non
        # coprono (FULLNAME/ORG/EMAIL/DATE) nel registro dei documenti di sicurezza
        ratio = len(self._with_pii()) / len(cy.TEMPLATES)
        self.assertGreaterEqual(ratio, 0.6, f"solo il {ratio:.0%} dei template ha PII")

    def test_some_templates_are_deliberately_pii_free(self):
        # righe tecniche pure (log, catene di indicatori): servono a insegnare che un
        # IP o un hash sono 'O'. Un modello che non ne ha mai visti puo' etichettarli
        # come qualcos'altro, ed e' un falso positivo che rende il testo illeggibile.
        without = len(cy.TEMPLATES) - len(self._with_pii())
        self.assertGreaterEqual(without, 3, "nessun esempio interamente 'O'")

    def test_registering_does_not_break_the_upstream_slots(self):
        before = dict(gen.SLOTS)
        cy.register()
        for name, fn in before.items():
            self.assertIs(gen.SLOTS[name], fn, name)


class TestStrayNameGuard(GeneratorTestCase):
    """Il filtro sul gergo tecnico e' additivo: il nucleo della guardia deve reggere.

    Il caso che conta e' l'ultimo — un cognome vero ACCANTO a un termine tecnico. Se
    passasse, il dataset conterrebbe un nome non etichettato e il modello imparerebbe
    a non vederlo."""

    def _rejected(self, text):
        return bool(cy.find_stray_names(text))

    def test_security_jargon_in_title_case_is_not_a_name(self):
        for benign in ("Security Operations Center attivo",
                       "Remote Code Execution e Vulnerability Assessment",
                       "Il Contenimento e l'Isolamento dell'Host",   # elisioni
                       "Threat Intelligence, Incident Response, Penetration Test"):
            self.assertFalse(self._rejected(benign), benign)

    def test_a_real_name_is_still_rejected(self):
        self.assertTrue(self._rejected("il perito Mario Rossi ha verificato"))

    def test_a_titled_name_with_the_dot_is_rejected(self):
        # caso che il guard upstream lascia passare: li' il salto di fine frase
        # scatta prima del controllo sui titoli
        self.assertTrue(self._rejected("Sig. Bianchi ha aperto il ticket"))
        self.assertTrue(self._rejected("Dott. Neri del reparto Incident Response"))

    def test_a_name_next_to_a_technical_term_is_still_rejected(self):
        self.assertTrue(self._rejected("l'analista Security Rossi conferma"))
        self.assertTrue(self._rejected("Security Operations Center di Mario Rossi"))

    def test_no_security_term_is_a_plausible_italian_surname(self):
        # criterio con cui l'elenco e' stato compilato: va applicato a ogni aggiunta
        surnames = {"Rossi", "Bianchi", "Ferrari", "Russo", "Esposito", "Romano",
                    "Costa", "Greco", "Bruno", "Gallo", "Conti", "Mancini", "Rizzo",
                    "Lombardi", "Moretti", "Barbieri", "Fontana", "Santoro", "Leone",
                    "Serra", "Villa", "Conte", "Bianco", "Longo", "Vitale", "Marino"}
        self.assertEqual(cy.SECURITY_CAPITALIZED & surnames, set())

    def test_a_placeholder_is_never_taken_for_a_name(self):
        self.assertFalse(self._rejected("Riferimento: {FULLNAME} di {ORG}"))


class TestTemplateBank(GeneratorTestCase):
    """La banca su disco e' cio' che rende utile una quota giornaliera piccola:
    senza, i template ottenuti oggi si buttano a fine esecuzione."""

    GOOD = ("Il {DATE} l'analista {FULLNAME} di {ORG} ha isolato "
            "l'host {HOSTNAME} ({IPADDR}).")
    WITH_NAME = "Il perito Mario Rossi ha verificato l'host {HOSTNAME}."
    WITH_LITERAL = "Il server {HOSTNAME} contatta 8.8.8.8, riferisce {FULLNAME}."

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "bank.json"

    def tearDown(self):
        self._tmp.cleanup()
        super().tearDown()

    def test_round_trip(self):
        self.assertEqual(cy.save_bank([self.GOOD], self.path), (1, 1))
        self.assertEqual(cy.load_bank(self.path), [self.GOOD])

    def test_duplicates_are_not_added_twice(self):
        cy.save_bank([self.GOOD], self.path)
        self.assertEqual(cy.save_bank([self.GOOD], self.path), (0, 1))

    def test_saving_accumulates_across_runs(self):
        other = "Ticket aperto da {FULLNAME} il {DATE} sull'host {HOSTNAME}."
        cy.save_bank([self.GOOD], self.path)
        self.assertEqual(cy.save_bank([other], self.path), (1, 2))
        self.assertEqual(len(cy.load_bank(self.path)), 2)

    def test_banked_templates_are_revalidated_on_load(self):
        # la banca sopravvive alle correzioni del codice: cio' che passava ieri va
        # riverificato, altrimenti un template diventato non valido rientra per sempre
        self.path.write_text(json.dumps([self.GOOD, self.WITH_NAME, self.WITH_LITERAL]),
                             "utf-8")
        self.assertEqual(cy.load_bank(self.path), [self.GOOD])

    def test_missing_file_gives_an_empty_bank(self):
        self.assertEqual(cy.load_bank(self.path), [])

    def test_corrupt_file_is_reported_and_ignored(self):
        self.path.write_text("{non json", "utf-8")
        self.assertEqual(cy.load_bank(self.path), [])

    def test_non_string_entries_are_ignored(self):
        self.path.write_text(json.dumps([self.GOOD, 42, None, {"t": "x"}]), "utf-8")
        self.assertEqual(cy.load_bank(self.path), [self.GOOD])


class TestTruncationGuard(GeneratorTestCase):
    """Rete di sicurezza timida: la verita' la dice finish_reason, non il testo.

    La versione precedente pretendeva punteggiatura terminale e su un campione di tre
    risposte ne scartava due, entrambe integre: nelle voci di elenco e nelle timeline
    la frase senza punto finale e' la norma, non un difetto."""

    def test_a_complete_sentence_without_a_full_stop_is_not_truncated(self):
        for ok in ("Rimozione di {FILEPATH} e cancellazione di {HASH} dal disco",
                   "Il piano verra' rivisto il {DATE} dopo il completamento",
                   "{DATE} {IPADDR} -> {IPADDR} {PORT} ICMP DENY regola=FW_Drop_Ping",
                   "Elenco:\n  - {IPADDR}\n  - {HASH}"):
            self.assertFalse(cy.looks_truncated(ok), ok)

    def test_a_dangling_function_word_is_truncated(self):
        for bad in ("applicazione di {CVE} su servizio esposto, esecuzione della",
                    "Le evidenze sono state raccolte e trasmesse a",
                    "Il contenimento e' stato applicato sul"):
            self.assertTrue(cy.looks_truncated(bad), bad)

    def test_a_broken_hyphenation_is_truncated(self):
        self.assertTrue(cy.looks_truncated("ha identificato un arte-"))

    def test_an_empty_template_is_truncated(self):
        self.assertTrue(cy.looks_truncated("   "))


class TestRecordShape(GeneratorTestCase):

    def test_rows_have_the_project_format(self):
        rows, _, _ = cy.build(50, cy.TEMPLATES, seed=3)
        for rec in rows:
            self.assertEqual(set(rec), {"source_text", "language", "template_id",
                                        "entities", "tokens", "bio_labels", "meta"})
            self.assertEqual(len(rec["tokens"]), len(rec["bio_labels"]))
            for e in rec["entities"]:
                self.assertEqual(rec["source_text"][e["start"]:e["end"]], e["value"])

    def test_bio_labels_are_well_formed(self):
        rows, _, _ = cy.build(50, cy.TEMPLATES, seed=4)
        for rec in rows:
            for lab in rec["bio_labels"]:
                self.assertTrue(lab == "O" or re.fullmatch(r"[BI]-[A-Z_]+", lab), lab)

    def test_entities_never_overlap(self):
        # to_bio tiene solo la PRIMA entita' che contiene un token e scarta le altre
        # in silenzio: sovrapporle significherebbe perderne una senza accorgersene
        rows, _, _ = cy.build(100, cy.TEMPLATES, seed=5)
        for rec in rows:
            spans = sorted((e["start"], e["end"]) for e in rec["entities"])
            for (_, end), (start, _) in zip(spans, spans[1:]):
                self.assertLessEqual(end, start, rec["source_text"][:80])


class TestLabellingMode(GeneratorTestCase):

    def test_by_default_cyber_values_are_not_labelled(self):
        self.assertIsNone(cy.ip_piece()[0][1])
        rows, counts, _ = cy.build(80, cy.TEMPLATES, seed=6)
        self.assertEqual(set(counts) & set(cy.CYBER_LABELS), set())

    def test_the_flag_turns_the_cyber_labels_on(self):
        cy.set_label_cyber(True)
        self.assertEqual(cy.ip_piece()[0][1], "IP")
        _, counts, _ = cy.build(80, cy.TEMPLATES, seed=6)
        self.assertTrue(set(counts) & set(cy.CYBER_LABELS))

    def test_pii_labels_are_the_same_in_both_modes(self):
        _, plain, _ = cy.build(120, cy.TEMPLATES, seed=11)
        cy.set_label_cyber(True)
        _, labelled, _ = cy.build(120, cy.TEMPLATES, seed=11)
        pii = {k: v for k, v in labelled.items() if k not in cy.CYBER_LABELS}
        self.assertEqual(plain, pii)

    def test_the_mode_is_recorded_in_the_metadata(self):
        rows, _, _ = cy.build(5, cy.TEMPLATES, seed=8)
        self.assertFalse(rows[0]["meta"]["cyber_labeled"])
        self.assertEqual(rows[0]["meta"]["genre"], "security")


class TestDetectorsSeeWhatWeGenerate(GeneratorTestCase):
    """Chiude il cerchio: i detector devono ritrovare i valori generati.

    Se non li ritrovassero, il dataset non misurerebbe la rete regex — e in
    produzione quei valori resterebbero in chiaro."""

    def _found(self, text):
        spans = []
        for _label, rx, validator, _strict in detectors_cyber.DETECTORS:
            for m in rx.finditer(text):
                if validator is None or validator(m.group()):
                    spans.append((m.start(), m.end()))
        return spans

    def test_generated_wallets_pass_our_own_base58check(self):
        for _ in range(100):
            self.assertTrue(detectors_cyber.btc_ok(cy.wallet_piece()[0][0]))

    def test_generated_ips_and_hashes_are_detected(self):
        cy.set_label_cyber(True)
        rows, _, _ = cy.build(150, cy.TEMPLATES, seed=9)
        total = missed = 0
        for rec in rows:
            spans = self._found(rec["source_text"])
            for e in rec["entities"]:
                if e["label"] not in ("IP", "HASH", "URL", "DOMAIN"):
                    continue
                total += 1
                if not any(s <= e["start"] and e["end"] <= t for s, t in spans):
                    missed += 1
        self.assertGreater(total, 200, "campione troppo piccolo per dire qualcosa")
        self.assertEqual(missed, 0, f"{missed}/{total} valori NON rilevati dai detector")


if __name__ == "__main__":
    unittest.main()
