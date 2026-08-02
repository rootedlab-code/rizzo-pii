# -*- coding: utf-8 -*-
"""
Test della policy quando la decisione dipende anche dal RUOLO (src/app/policy.py).

Il caso che motiva tutto: in un report di sicurezza l'IP del cliente e quello
dell'attaccante hanno lo stesso tag e trattamento opposto. keep_tags e'
incondizionata, keep_roles la raffina.

I test della policy "storica" stanno in test_policy.py e NON sono stati toccati:
e' li' che si vede che il default non cambia.

Solo stdlib: nessun modello, nessuna rete.

    python -m unittest discover -s tests
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "app"))

import policy  # noqa: E402
import scope   # noqa: E402

TAXONOMY = {"FULLNAME", "EMAIL", "AGE", "IP", "DOMAIN", "URL", "HASH",
            "WALLET", "ASN", "MAC", "CLOUDID", "PATH", "USER"}

OWN = scope.ROLE_OWN
ADVERSARY = scope.ROLE_ADVERSARY
UNKNOWN = scope.ROLE_UNKNOWN


class RolePolicyTestCase(unittest.TestCase):
    """Stesso isolamento di PolicyTestCase: env pulita, config dir temporanea."""

    def setUp(self):
        self._env = {k: os.environ.pop(k) for k in ("PII_PROFILE", "PII_KEEP_TAGS")
                     if k in os.environ}
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_config_dir = policy.server_config.config_dir
        policy.server_config.config_dir = lambda: Path(self._tmp.name)
        self.warnings = []

    def tearDown(self):
        policy.server_config.config_dir = self._orig_config_dir
        self._tmp.cleanup()
        os.environ.update(self._env)
        for k in ("PII_PROFILE", "PII_KEEP_TAGS"):
            if k not in self._env:
                os.environ.pop(k, None)

    def load(self, **kwargs):
        kwargs.setdefault("warn", self.warnings.append)
        return policy.load_policy(**kwargs)


class TestParseRoles(RolePolicyTestCase):

    def test_roles_are_lowercased_and_tags_uppercased(self):
        self.assertEqual(policy.parse_roles({" Adversary ": "ip, domain"}),
                         {"adversary": ("IP", "DOMAIN")})

    def test_empty_tag_list_drops_the_role(self):
        self.assertEqual(policy.parse_roles({"adversary": []}), {})

    def test_none_and_empty_give_an_empty_mapping(self):
        self.assertEqual(policy.parse_roles(None), {})
        self.assertEqual(policy.parse_roles({}), {})

    def test_non_mapping_raises(self):
        with self.assertRaises(TypeError):
            policy.parse_roles(["adversary"])


class TestDecide(RolePolicyTestCase):

    def test_role_rule_keeps_only_for_that_role(self):
        p = policy.Policy(keep_roles={ADVERSARY: ["IP"]})
        self.assertEqual(p.decide("IP", ADVERSARY),
                         policy.Decision(policy.ACTION_KEEP, policy.REASON_SCOPE))
        self.assertEqual(p.decide("IP", OWN).action, policy.ACTION_MASK)
        self.assertEqual(p.decide("IP", UNKNOWN).action, policy.ACTION_MASK)

    def test_unrelated_tag_is_masked_even_for_a_configured_role(self):
        p = policy.Policy(keep_roles={ADVERSARY: ["IP"]})
        self.assertEqual(p.decide("DOMAIN", ADVERSARY).action, policy.ACTION_MASK)

    def test_keep_tags_is_unconditional_and_reported_as_config(self):
        p = policy.Policy(keep_tags=["IP"], keep_roles={ADVERSARY: ["IP"]})
        for role in (None, OWN, ADVERSARY, UNKNOWN):
            self.assertEqual(p.decide("IP", role),
                             policy.Decision(policy.ACTION_KEEP, policy.REASON_CONFIG))

    def test_masked_decision_carries_no_reason(self):
        self.assertEqual(policy.Policy().decide("IP", ADVERSARY),
                         policy.Decision(policy.ACTION_MASK, None))

    def test_without_role_only_keep_tags_applies(self):
        p = policy.Policy(keep_roles={ADVERSARY: ["IP"]})
        self.assertEqual(p.action("IP"), policy.ACTION_MASK)
        self.assertFalse(p.keeps("IP"))

    def test_action_and_keeps_accept_the_role(self):
        p = policy.Policy(keep_roles={ADVERSARY: ["IP"]})
        self.assertEqual(p.action("IP", ADVERSARY), policy.ACTION_KEEP)
        self.assertTrue(p.keeps("IP", ADVERSARY))
        self.assertFalse(p.keeps("IP", OWN))


class TestSecurityReportProfile(RolePolicyTestCase):

    def test_adversary_indicators_stay_in_clear_and_the_client_does_not(self):
        p = self.load(cli_profile="security-report", known_tags=TAXONOMY)
        for tag in ("IP", "DOMAIN", "URL", "HASH"):
            self.assertTrue(p.keeps(tag, ADVERSARY), tag)
            self.assertFalse(p.keeps(tag, OWN), tag)
            self.assertFalse(p.keeps(tag, UNKNOWN), tag)

    def test_paths_and_users_are_masked_even_for_the_adversary(self):
        # un percorso contiene spesso lo username di una macchina del cliente
        p = self.load(cli_profile="security-report", known_tags=TAXONOMY)
        self.assertFalse(p.keeps("PATH", ADVERSARY))
        self.assertFalse(p.keeps("USER", ADVERSARY))

    def test_the_profile_keeps_no_tag_unconditionally(self):
        p = self.load(cli_profile="security-report", known_tags=TAXONOMY)
        self.assertEqual(p.keep_tags, frozenset())

    def test_other_profiles_have_no_role_rules(self):
        p = self.load(cli_profile="clinical", known_tags=TAXONOMY)
        self.assertEqual(p.keep_roles, {})


class TestResolution(RolePolicyTestCase):

    def test_file_roles_extend_the_profile_roles(self):
        policy.save_file("security-report", [], {ADVERSARY: ["PATH"]})
        p = self.load(known_tags=TAXONOMY)
        self.assertTrue(p.keeps("IP", ADVERSARY))       # dal profilo
        self.assertTrue(p.keeps("PATH", ADVERSARY))     # dal file

    def test_file_roles_work_without_any_profile(self):
        policy.save_file("full", [], {ADVERSARY: ["IP"]})
        p = self.load(known_tags=TAXONOMY)
        self.assertTrue(p.keeps("IP", ADVERSARY))
        self.assertFalse(p.keeps("IP", OWN))

    def test_unknown_role_is_warned_and_dropped(self):
        policy.save_file("full", [], {"amico": ["IP"]})
        p = self.load(known_tags=TAXONOMY)
        self.assertEqual(p.keep_roles, {})
        self.assertTrue(any("amico" in w for w in self.warnings))

    def test_tag_outside_the_taxonomy_is_warned_and_dropped(self):
        policy.save_file("full", [], {ADVERSARY: ["IP", "NONESISTE"]})
        p = self.load(known_tags=TAXONOMY)
        self.assertEqual(p.keep_roles, {ADVERSARY: frozenset({"IP"})})
        self.assertTrue(any("NONESISTE" in w for w in self.warnings))

    def test_role_whose_tags_are_all_dropped_disappears(self):
        policy.save_file("full", [], {ADVERSARY: ["NONESISTE"]})
        p = self.load(known_tags=TAXONOMY)
        self.assertEqual(p.keep_roles, {})

    def test_malformed_keep_roles_is_warned_not_fatal(self):
        policy.policy_path().write_text('{"profile": "full", "keep_roles": ["IP"]}', "utf-8")
        p = self.load(known_tags=TAXONOMY)
        self.assertEqual(p.keep_roles, {})
        self.assertTrue(any("keep_roles" in w for w in self.warnings))


class TestSerialization(RolePolicyTestCase):

    def test_as_dict_omits_keep_roles_when_there_are_none(self):
        p = policy.Policy(keep_tags=["AGE"], profile="clinical")
        self.assertEqual(p.as_dict(), {"profile": "clinical", "keep_tags": ["AGE"]})

    def test_as_dict_includes_keep_roles_when_present(self):
        p = policy.Policy(keep_roles={ADVERSARY: ["DOMAIN", "IP"]})
        self.assertEqual(p.as_dict()["keep_roles"], {ADVERSARY: ["DOMAIN", "IP"]})

    def test_save_file_omits_keep_roles_when_there_are_none(self):
        policy.save_file("full", ["AGE"])
        self.assertEqual(policy.load_file(), {"profile": "full", "keep_tags": ["AGE"]})

    def test_save_and_load_file_round_trip_with_roles(self):
        policy.save_file("full", [], {" Adversary ": "ip, domain"})
        self.assertEqual(policy.load_file(),
                         {"profile": "full", "keep_tags": [],
                          "keep_roles": {ADVERSARY: ["IP", "DOMAIN"]}})


if __name__ == "__main__":
    unittest.main()
