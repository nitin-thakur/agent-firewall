import unittest

from attacks.scenarios import SCENARIOS
from runner import run_scenario
import config
from tests.base import IsolatedLogsTestCase

PHASE3 = config.BASE_DIR / "policies" / "policy_phase3.yaml"


class ScenarioTests(IsolatedLogsTestCase):
    def run_sc(self, name, firewall, policy=None):
        return run_scenario(SCENARIOS[name], "mock", firewall, verbose=False, policy_path=policy)

    def test_attacks_succeed_without_firewall(self):
        self.assertTrue(self.run_sc("attack_exfil", False).success)
        self.assertTrue(self.run_sc("attack_payment", False).success)

    def test_attacks_stopped_with_firewall(self):
        self.assertFalse(self.run_sc("attack_exfil", True).success)
        self.assertFalse(self.run_sc("attack_payment", True).success)

    def test_benign_task_works_both_ways(self):
        self.assertTrue(self.run_sc("benign_summary", False).success)
        self.assertTrue(self.run_sc("benign_summary", True).success)

    # ---- Phase 4: attacks that slip past the old Phase 3 policy ----
    def test_secret_in_body_beats_phase3_but_not_phase4(self):
        self.assertTrue(self.run_sc("attack_secret_in_body", True, PHASE3).success)
        self.assertFalse(self.run_sc("attack_secret_in_body", True).success)

    def test_payment_loop_phase3_loses_1200_phase4_limits_to_800(self):
        r3 = self.run_sc("attack_payment_loop", True, PHASE3)
        self.assertTrue(r3.success)
        self.assertEqual(sum(p["amount"] for p in r3.payments), 1200)
        r4 = self.run_sc("attack_payment_loop", True)
        self.assertFalse(r4.success)
        # Honest limit of Phase 4: the first payments to an allowed payee still go through.
        self.assertEqual(sum(p["amount"] for p in r4.payments), 800)

    def test_verdict_is_honest_about_partial_damage(self):
        r4 = self.run_sc("attack_payment_loop", True)
        self.assertIn("LIMITED", r4.verdict)
        self.assertIn("800", r4.verdict)
        self.assertEqual(self.run_sc("attack_exfil", True).verdict, "attack stopped (good)")

    def test_new_attacks_succeed_without_firewall(self):
        self.assertTrue(self.run_sc("attack_secret_in_body", False).success)
        self.assertTrue(self.run_sc("attack_payment_loop", False).success)

    def test_benign_task_works_under_phase4_policy(self):
        self.assertTrue(self.run_sc("benign_summary", True).success)


if __name__ == "__main__":
    unittest.main()
