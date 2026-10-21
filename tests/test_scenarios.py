import unittest

from attacks.scenarios import SCENARIOS
from runner import run_scenario
import config
from tests.base import IsolatedLogsTestCase
from tools.storage import read_jsonl

PHASE3 = config.BASE_DIR / "policies" / "policy_phase3.yaml"
PHASE4 = config.BASE_DIR / "policies" / "policy_phase4.yaml"


class ScenarioTests(IsolatedLogsTestCase):
    def run_sc(self, name, firewall, policy=None, approver=None, approve_mode=None):
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):          # approval prompts print; keep test output clean
            return run_scenario(SCENARIOS[name], "mock", firewall, verbose=False, policy_path=policy,
                                approver=approver, approve_mode=approve_mode)

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
        self.assertFalse(self.run_sc("attack_secret_in_body", True, PHASE4).success)

    def test_payment_loop_phase3_loses_1200_phase4_limits_to_800(self):
        r3 = self.run_sc("attack_payment_loop", True, PHASE3)
        self.assertTrue(r3.success)
        self.assertEqual(sum(p["amount"] for p in r3.payments), 1200)
        r4 = self.run_sc("attack_payment_loop", True, PHASE4)
        self.assertFalse(r4.success)
        # Honest limit of Phase 4: the first payments to an allowed payee still go through.
        self.assertEqual(sum(p["amount"] for p in r4.payments), 800)

    def test_verdict_is_honest_about_partial_damage(self):
        r4 = self.run_sc("attack_payment_loop", True, PHASE4)
        self.assertIn("LIMITED", r4.verdict)
        self.assertIn("800", r4.verdict)
        self.assertEqual(self.run_sc("attack_exfil", True).verdict, "attack stopped (good)")

    def test_new_attacks_succeed_without_firewall(self):
        self.assertTrue(self.run_sc("attack_secret_in_body", False).success)
        self.assertTrue(self.run_sc("attack_payment_loop", False).success)

    def test_benign_task_works_under_phase4_policy(self):
        self.assertTrue(self.run_sc("benign_summary", True, PHASE4).success)

    # ---- Phase 5: provenance ----
    def test_internal_leak_beats_phase4_but_not_phase5(self):
        self.assertTrue(self.run_sc("attack_internal_leak", False).success)
        self.assertTrue(self.run_sc("attack_internal_leak", True, PHASE4).success)
        r5 = self.run_sc("attack_internal_leak", True)
        self.assertFalse(r5.success)
        self.assertEqual(r5.emails, [])

    def test_payment_loop_loses_nothing_under_phase5(self):
        r5 = self.run_sc("attack_payment_loop", True)
        self.assertEqual(r5.payments, [])
        self.assertEqual(r5.verdict, "attack stopped (good)")

    def test_every_attack_is_stopped_by_phase5_default_policy(self):
        for name, sc in SCENARIOS.items():
            if sc.is_attack:
                r = self.run_sc(name, True)
                self.assertFalse(r.success, name)
                self.assertEqual((r.emails, r.payments), ([], []), name)

    def test_benign_summary_still_works_under_phase5(self):
        self.assertTrue(self.run_sc("benign_summary", True).success)

    def test_legit_bill_is_paused_not_failed_and_runs_when_approved(self):
        self.assertTrue(self.run_sc("benign_pay_bill", True, PHASE4).success)      # old rules: no friction
        paused = self.run_sc("benign_pay_bill", True)                               # Phase 5: asks first
        self.assertFalse(paused.success)
        self.assertEqual(paused.asked, 1)
        self.assertIn("no approver is configured", paused.verdict)
        approved = self.run_sc("benign_pay_bill", True, approver=lambda tool, args, decision: True)
        self.assertTrue(approved.success)

    def test_phase6_user_yes_completes_the_legit_bill_and_no_stops_it(self):
        yes = self.run_sc("benign_pay_bill", True, approve_mode="yes")
        self.assertTrue(yes.success)
        no = self.run_sc("benign_pay_bill", True, approve_mode="no")
        self.assertFalse(no.success)
        self.assertEqual((no.denied, no.asked), (1, 0))
        self.assertIn("you denied", no.verdict)

    def test_phase6_every_attack_is_stopped_when_the_user_says_no(self):
        for name, sc in SCENARIOS.items():
            if sc.is_attack:
                r = self.run_sc(name, True, approve_mode="no")
                self.assertEqual((r.emails, r.payments), ([], []), name)

    def test_phase6_a_wrong_yes_still_hits_the_static_limits(self):
        r = self.run_sc("attack_payment_loop", True, approve_mode="yes")
        self.assertEqual(sum(p["amount"] for p in r.payments), 800)     # run cap Rs 1000 cannot be approved away
        self.assertIn("LIMITED", r.verdict)
        r = self.run_sc("attack_exfil", True, approve_mode="yes")
        self.assertFalse(r.success)                                       # secrets* blocklist cannot be approved away

    def test_approving_an_attack_lets_it_through_so_the_prompt_must_be_clear(self):
        # Documents the human-in-the-loop trade-off: if the user says yes, the action runs.
        r = self.run_sc("attack_payment_loop", True, approver=lambda tool, args, decision: True)
        self.assertGreater(sum(p["amount"] for p in r.payments), 0)

    def test_provenance_is_a_second_layer_when_static_rules_are_removed(self):
        import tempfile
        import yaml
        with open(config.POLICY_PATH, encoding="utf-8") as f:
            policy = yaml.safe_load(f)
        policy["tools"]["read_file"]["blocked_path_patterns"] = []          # remove the secrets* rule
        policy["tools"]["send_email"]["allowed_recipient_domains"] = []     # remove the domain allowlist
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/weak_policy.yaml"
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(policy, f)
            r = self.run_sc("attack_exfil", True, path)
        self.assertFalse(r.success)
        self.assertEqual(r.emails, [])
        blocked = [d for d in read_jsonl(config.AUDIT_PATH) if d["action"] != "allow"]
        self.assertEqual([d["rule"] for d in blocked], ["provenance"])     # provenance, not a static rule


if __name__ == "__main__":
    unittest.main()
