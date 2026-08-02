# -*- coding: utf-8 -*-
"""
Test del modulo di scope (src/app/scope.py).

Nessuno stub: scope.py e detectors_cyber sono puri, girano senza modello.
Tutti i valori vengono dagli intervalli riservati alla documentazione — RFC 5737
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), RFC 3849 (2001:db8::/32),
RFC 1918 (10.0.0.0/8) e RFC 2606 (.example) — mai da un caso reale.

    python -m unittest discover -s tests
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))

import scope  # noqa: E402

CLIENT_IP = "203.0.113.5"
ADVERSARY_IP = "198.51.100.7"
CLIENT_NET = "10.0.0.0/8"


def _scope(**lists):
    """Scope di sole liste: il contesto e' spento, com'e' di default."""
    return scope.Scope(lists=lists)


def _ctx_scope(roles=(scope.ROLE_ADVERSARY, scope.ROLE_OWN), **kwargs):
    """Scope con il contesto ACCESO per i ruoli indicati (opt-in esplicito)."""
    return scope.Scope(context_roles=roles, **kwargs)


class TestListsWin(unittest.TestCase):
    """Le liste esplicite decidono per prime, sempre."""

    def test_exact_ip_in_own_list_is_own(self):
        s = _scope(own={"IP": [CLIENT_IP]})
        self.assertEqual(s.role_of("IP", CLIENT_IP),
                         scope.ScopeMatch(scope.ROLE_OWN, scope.SOURCE_LIST))

    def test_ip_inside_a_listed_cidr_is_own(self):
        s = _scope(own={"IP": [CLIENT_NET]})
        self.assertEqual(s.role_of("IP", "10.4.2.1").role, scope.ROLE_OWN)

    def test_ip_outside_a_listed_cidr_is_unknown(self):
        s = _scope(own={"IP": [CLIENT_NET]})
        self.assertEqual(s.role_of("IP", "11.4.2.1").role, scope.ROLE_UNKNOWN)

    def test_cidr_value_is_own_only_when_subnet_of_a_listed_network(self):
        s = _scope(own={"IP": [CLIENT_NET]})
        self.assertEqual(s.role_of("IP", "10.4.0.0/16").role, scope.ROLE_OWN)
        self.assertEqual(s.role_of("IP", "172.16.0.0/16").role, scope.ROLE_UNKNOWN)

    def test_ipv6_and_ipv4_do_not_match_across_families(self):
        s = _scope(own={"IP": ["2001:db8::/32"]})
        self.assertEqual(s.role_of("IP", "2001:db8::1").role, scope.ROLE_OWN)
        self.assertEqual(s.role_of("IP", CLIENT_IP).role, scope.ROLE_UNKNOWN)

    def test_defanged_value_matches_the_plain_entry(self):
        s = _scope(adversary={"IP": [ADVERSARY_IP]})
        self.assertEqual(s.role_of("IP", "198[.]51[.]100[.]7").role, scope.ROLE_ADVERSARY)

    def test_context_does_not_override_an_explicit_list(self):
        # contesto ACCESO e indizi che direbbero 'adversary': vince comunque la lista
        s = _ctx_scope(lists={scope.ROLE_OWN: {"IP": [CLIENT_IP]}})
        text = f"Il C2 dell'attaccante risponde su {CLIENT_IP} secondo il log."
        match = s.role_of("IP", CLIENT_IP, text, text.index(CLIENT_IP),
                          text.index(CLIENT_IP) + len(CLIENT_IP))
        self.assertEqual(match, scope.ScopeMatch(scope.ROLE_OWN, scope.SOURCE_LIST))


class TestDomains(unittest.TestCase):

    def test_subdomain_of_a_listed_domain_matches(self):
        s = _scope(own={"DOMAIN": ["cliente.example"]})
        self.assertEqual(s.role_of("DOMAIN", "mail.cliente.example").role, scope.ROLE_OWN)

    def test_domain_sharing_only_a_string_suffix_does_not_match(self):
        # 'evilcliente.example' NON e' un sottodominio di 'cliente.example'
        s = _scope(own={"DOMAIN": ["cliente.example"]})
        self.assertEqual(s.role_of("DOMAIN", "evilcliente.example").role,
                         scope.ROLE_UNKNOWN)

    def test_parent_of_a_listed_domain_does_not_match(self):
        s = _scope(own={"DOMAIN": ["mail.cliente.example"]})
        self.assertEqual(s.role_of("DOMAIN", "cliente.example").role, scope.ROLE_UNKNOWN)

    def test_url_inherits_the_role_of_its_host_domain(self):
        s = _scope(adversary={"DOMAIN": ["evil.example"]})
        self.assertEqual(s.role_of("URL", "https://evil.example/beacon").role,
                         scope.ROLE_ADVERSARY)

    def test_url_host_is_matched_through_port_and_credentials(self):
        s = _scope(adversary={"DOMAIN": ["evil.example"]})
        self.assertEqual(s.role_of("URL", "https://user:pw@evil.example:8443/x").role,
                         scope.ROLE_ADVERSARY)

    def test_defanged_url_scheme_is_understood(self):
        s = _scope(adversary={"DOMAIN": ["evil.example"]})
        self.assertEqual(s.role_of("URL", "hxxps://evil[.]example/beacon").role,
                         scope.ROLE_ADVERSARY)


class ContextTestCase(unittest.TestCase):

    def _match(self, s, value, text, label="IP"):
        start = text.index(value)
        return s.role_of(label, value, text, start, start + len(value))


class TestContextIsOptIn(ContextTestCase):
    """Un'euristica non sblocca il 'lascia in chiaro' da sola: va dichiarata."""

    def test_cues_do_nothing_until_a_role_is_enabled(self):
        text = f"Il C2 risponde su {ADVERSARY_IP} ogni 60 secondi."
        self.assertEqual(self._match(_scope(), ADVERSARY_IP, text),
                         scope.ScopeMatch(scope.ROLE_UNKNOWN, scope.SOURCE_DEFAULT))

    def test_only_the_enabled_roles_can_be_assigned(self):
        s = scope.Scope(context_roles=(scope.ROLE_OWN,))
        text = f"Il C2 risponde su {ADVERSARY_IP} ogni 60 secondi."
        self.assertEqual(self._match(s, ADVERSARY_IP, text).role, scope.ROLE_UNKNOWN)
        text2 = f"Il server interno del cliente e' {CLIENT_IP}."
        self.assertEqual(self._match(s, CLIENT_IP, text2).role, scope.ROLE_OWN)

    def test_an_unknown_role_in_the_opt_in_enables_nothing(self):
        s = scope.Scope(context_roles=("amico",))
        text = f"Il C2 risponde su {ADVERSARY_IP}."
        self.assertEqual(self._match(s, ADVERSARY_IP, text).role, scope.ROLE_UNKNOWN)


class TestContext(ContextTestCase):
    """Comportamento degli indizi quando il contesto e' stato acceso."""

    def test_adversary_cue_near_the_value_assigns_adversary(self):
        text = f"Il C2 risponde su {ADVERSARY_IP} ogni 60 secondi."
        self.assertEqual(self._match(_ctx_scope(), ADVERSARY_IP, text),
                         scope.ScopeMatch(scope.ROLE_ADVERSARY, scope.SOURCE_CONTEXT))

    def test_own_cue_near_the_value_assigns_own(self):
        text = f"Il server interno del cliente ha indirizzo {CLIENT_IP}."
        self.assertEqual(self._match(_ctx_scope(), CLIENT_IP, text).role, scope.ROLE_OWN)

    def test_cues_of_two_roles_in_the_window_give_unknown(self):
        # la frase parla di entrambe le parti: il contesto non puo' decidere
        text = f"Il C2 dell'attaccante ha colpito il server del cliente {CLIENT_IP}."
        self.assertEqual(self._match(_ctx_scope(), CLIENT_IP, text),
                         scope.ScopeMatch(scope.ROLE_UNKNOWN, scope.SOURCE_DEFAULT))

    def test_ambiguity_is_judged_on_all_cues_not_only_the_enabled_ones(self):
        # 'own' non e' abilitato, ma il suo indizio deve comunque rendere ambigua la
        # frase: filtrarlo prima farebbe passare 'adversary' su una frase che nomina
        # anche il cliente — cioe' lascerebbe in chiaro proprio il caso dubbio.
        s = scope.Scope(context_roles=(scope.ROLE_ADVERSARY,))
        text = f"Il C2 dell'attaccante ha colpito il server del cliente {CLIENT_IP}."
        self.assertEqual(self._match(s, CLIENT_IP, text).role, scope.ROLE_UNKNOWN)

    def test_cue_outside_the_window_is_ignored(self):
        s = _ctx_scope(window=5)
        text = f"Il C2 {'.' * 80} contatta {ADVERSARY_IP}."
        self.assertEqual(self._match(s, ADVERSARY_IP, text).role, scope.ROLE_UNKNOWN)

    def test_no_offsets_means_no_context_lookup(self):
        self.assertEqual(_ctx_scope().role_of("IP", ADVERSARY_IP).role, scope.ROLE_UNKNOWN)

    def test_custom_cues_replace_the_defaults(self):
        s = _ctx_scope(cues={scope.ROLE_ADVERSARY: ["cavallo di troia"]})
        text = f"Il C2 risponde su {ADVERSARY_IP}."
        self.assertEqual(self._match(s, ADVERSARY_IP, text).role, scope.ROLE_UNKNOWN)
        text2 = f"Il cavallo di troia contatta {ADVERSARY_IP}."
        self.assertEqual(self._match(s, ADVERSARY_IP, text2).role, scope.ROLE_ADVERSARY)


class TestContradictions(unittest.TestCase):

    def test_same_value_in_two_roles_raises(self):
        with self.assertRaises(scope.ScopeError) as ctx:
            _scope(own={"IP": [CLIENT_IP]}, adversary={"IP": [CLIENT_IP]})
        self.assertIn(CLIENT_IP, str(ctx.exception))

    def test_same_value_under_different_tags_is_not_a_contradiction(self):
        s = _scope(own={"IP": [CLIENT_IP]}, adversary={"USER": [CLIENT_IP]})
        self.assertEqual(s.role_of("IP", CLIENT_IP).role, scope.ROLE_OWN)

    def test_same_value_twice_in_the_same_role_is_allowed(self):
        s = _scope(own={"IP": [CLIENT_IP, CLIENT_IP]})
        self.assertEqual(s.role_of("IP", CLIENT_IP).role, scope.ROLE_OWN)


class TestIntrospection(unittest.TestCase):

    def test_counts_report_how_many_never_which(self):
        s = _scope(own={"IP": [CLIENT_IP, CLIENT_NET]}, adversary={"DOMAIN": ["evil.example"]})
        self.assertEqual(s.counts(), {"own": {"IP": 2}, "adversary": {"DOMAIN": 1}})
        self.assertNotIn(CLIENT_IP, json.dumps(s.as_dict()))

    def test_empty_scope_is_reported_as_empty(self):
        self.assertTrue(scope.Scope().is_empty())
        self.assertFalse(_scope(own={"IP": [CLIENT_IP]}).is_empty())


class TestLoad(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scope.json"
        self.warnings = []

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, payload):
        self.path.write_text(json.dumps(payload), "utf-8")
        return self.path

    def load(self):
        return scope.load_scope(str(self.path), warn=self.warnings.append)

    def test_no_path_configured_gives_an_empty_scope(self):
        s = scope.load_scope(None, warn=self.warnings.append)
        self.assertTrue(s.is_empty())
        self.assertEqual(s.role_of("IP", CLIENT_IP).role, scope.ROLE_UNKNOWN)

    def test_missing_file_raises_instead_of_being_ignored(self):
        with self.assertRaises(scope.ScopeError):
            scope.load_scope(str(self.path), warn=self.warnings.append)

    def test_malformed_json_raises(self):
        self.path.write_text("{non e' json", "utf-8")
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_round_trip_of_lists_and_context(self):
        self.write({"own": {"IP": [CLIENT_NET]},
                    "adversary": {"DOMAIN": ["evil.example"]},
                    "context": {"roles": ["adversary"], "window": 10,
                                "cues": {"adversary": ["beacon"]}}})
        s = self.load()
        self.assertEqual(s.role_of("IP", "10.1.2.3").role, scope.ROLE_OWN)
        self.assertEqual(s.role_of("DOMAIN", "a.evil.example").role, scope.ROLE_ADVERSARY)
        self.assertEqual(s.window, 10)
        self.assertEqual(s.context_roles, (scope.ROLE_ADVERSARY,))

    def test_context_block_without_roles_enables_nothing(self):
        self.write({"context": {"window": 10, "cues": {"adversary": ["beacon"]}}})
        s = self.load()
        self.assertEqual(s.context_roles, ())
        text = f"Un beacon verso {ADVERSARY_IP} ogni ora."
        i = text.index(ADVERSARY_IP)
        self.assertEqual(s.role_of("IP", ADVERSARY_IP, text, i, i + len(ADVERSARY_IP)).role,
                         scope.ROLE_UNKNOWN)
        self.assertTrue(any("resta spento" in w for w in self.warnings))

    def test_unknown_role_in_context_roles_is_warned_and_dropped(self):
        self.write({"context": {"roles": ["adversary", "amico"]}})
        s = self.load()
        self.assertEqual(s.context_roles, (scope.ROLE_ADVERSARY,))
        self.assertTrue(any("amico" in w for w in self.warnings))

    def test_context_roles_must_be_a_list(self):
        self.write({"context": {"roles": "adversary"}})
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_unknown_top_level_key_is_warned_and_ignored(self):
        self.write({"own": {"IP": [CLIENT_IP]}, "amici": {"IP": ["192.0.2.1"]}})
        s = self.load()
        self.assertTrue(any("amici" in w for w in self.warnings))
        self.assertEqual(s.role_of("IP", "192.0.2.1").role, scope.ROLE_UNKNOWN)

    def test_wrong_type_for_a_role_raises(self):
        self.write({"own": ["203.0.113.5"]})
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_string_instead_of_list_raises(self):
        self.write({"own": {"IP": CLIENT_IP}})
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_negative_window_raises(self):
        self.write({"context": {"window": -1}})
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_contradictory_file_raises_at_load(self):
        self.write({"own": {"IP": [CLIENT_IP]}, "adversary": {"IP": [CLIENT_IP]}})
        with self.assertRaises(scope.ScopeError):
            self.load()

    def test_env_var_is_used_when_no_cli_path(self):
        import os
        self.write({"own": {"IP": [CLIENT_IP]}})
        os.environ[scope.ENV_SCOPE_FILE] = str(self.path)
        try:
            s = scope.load_scope(None, warn=self.warnings.append)
            self.assertEqual(s.role_of("IP", CLIENT_IP).role, scope.ROLE_OWN)
        finally:
            del os.environ[scope.ENV_SCOPE_FILE]


if __name__ == "__main__":
    unittest.main()
