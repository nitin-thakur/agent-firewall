import unittest

import config
from firewall.audit import AuditLog
from firewall.engine import Firewall
from firewall.policy import load_policy, validate_policy
from tests.base import IsolatedLogsTestCase
from tools.registry import execute_tool
from tools.storage import read_jsonl


class FirewallDecisionTests(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall(load_policy(config.POLICY_PATH))

    def action(self, tool, **args):
        return self.fw.evaluate(tool, args).action

    def test_read_allowed_and_blocked(self):
        self.assertEqual(self.action("read_file", path="notes/meeting_notes.txt"), "allow")
        for p in ("secrets.txt", "sandbox/secrets.txt", "SECRETS.TXT", ".env", "keys/server.pem", "../x.txt"):
            self.assertEqual(self.action("read_file", path=p), "block", p)

    def test_email_recipient_allowlist(self):
        self.assertEqual(self.action("send_email", to="boss@company.com", subject="s", body="b"), "allow")
        self.assertEqual(self.action("send_email", to="x@team.company.com", subject="s", body="b"), "allow")
        for to in ("a@evil-example.net", "a@notcompany.com", "a@company.com.evil.net", "nope"):
            self.assertEqual(self.action("send_email", to=to, subject="s", body="b"), "block", to)

    def test_email_secret_attachment_blocked(self):
        self.assertEqual(self.action("send_email", to="boss@company.com", subject="s", body="b",
                                     attachment_path="secrets.txt"), "block")

    def test_payment_rules(self):
        self.assertEqual(self.action("make_payment", payee="rent@upi", amount=300), "allow")
        self.assertEqual(self.action("make_payment", payee="rent@upi", amount=800), "ask")
        self.assertEqual(self.action("make_payment", payee="attacker@upi", amount=1), "block")
        self.assertEqual(self.action("make_payment", payee="rent@upi", amount="lots"), "block")

    def test_unknown_tool_uses_default_action(self):
        self.assertEqual(self.action("format_disk"), "block")

    def test_policy_validation(self):
        with self.assertRaises(ValueError):
            validate_policy({"tools": {"read_file": {"action": "maybe"}}})
        with self.assertRaises(ValueError):
            validate_policy({"tools": {"read_file": {"typo_key": 1}}})


class FirewallEnforcementTests(IsolatedLogsTestCase):
    def make(self, approver=None):
        return Firewall(load_policy(config.POLICY_PATH), AuditLog(run_id="t"), approver)

    def test_blocked_call_never_executes_and_is_logged(self):
        out = self.make().guard("send_email", {"to": "a@evil.net", "subject": "s", "body": "b"}, execute_tool)
        self.assertTrue(out.startswith("BLOCKED"))
        self.assertEqual(read_jsonl(config.OUTBOX_PATH), [])
        self.assertEqual(read_jsonl(config.AUDIT_PATH)[0]["action"], "block")

    def test_allowed_call_executes_and_is_logged(self):
        self.make().guard("send_email", {"to": "boss@company.com", "subject": "s", "body": "b"}, execute_tool)
        self.assertEqual(len(read_jsonl(config.OUTBOX_PATH)), 1)
        self.assertEqual(read_jsonl(config.AUDIT_PATH)[0]["action"], "allow")

    def test_ask_is_blocked_without_approver(self):
        out = self.make().guard("make_payment", {"payee": "rent@upi", "amount": 800}, execute_tool)
        self.assertTrue(out.startswith("BLOCKED"))
        self.assertEqual(read_jsonl(config.PAYMENTS_PATH), [])

    def test_ask_runs_when_approver_says_yes(self):
        fw = self.make(approver=lambda tool, args, decision: True)
        fw.guard("make_payment", {"payee": "rent@upi", "amount": 800}, execute_tool)
        self.assertEqual(len(read_jsonl(config.PAYMENTS_PATH)), 1)


if __name__ == "__main__":
    unittest.main()


class Phase4RuleTests(IsolatedLogsTestCase):
    def make(self):
        return Firewall(load_policy(config.POLICY_PATH), AuditLog(run_id="p4"))

    def email(self, fw, **kw):
        args = {"to": "boss@company.com", "subject": "s", "body": "hello"}
        args.update(kw)
        return fw.guard("send_email", args, execute_tool)

    def test_email_call_limit(self):
        fw = self.make()
        for _ in range(3):
            self.assertTrue(self.email(fw).startswith("[MOCK]"))
        out = self.email(fw)
        self.assertTrue(out.startswith("BLOCKED"))
        self.assertIn("call limit", out)
        self.assertEqual(len(read_jsonl(config.OUTBOX_PATH)), 3)

    def test_blocked_calls_do_not_use_up_the_limit(self):
        fw = self.make()
        for _ in range(5):
            self.email(fw, to="x@evil.net")           # all blocked
        self.assertTrue(self.email(fw).startswith("[MOCK]"))

    def test_email_body_too_long(self):
        out = self.email(self.make(), body="a" * 1001)
        self.assertIn("limit 1000", out)

    def test_email_body_with_secret_patterns(self):
        fw = self.make()
        for body in ("API_KEY=abc123", "my password: hunter2", "token sk-demo-1234567890",
                     "-----BEGIN RSA PRIVATE KEY-----", "PAN ABCDE1234F", "Aadhaar 1234 5678 9012"):
            self.assertTrue(self.email(fw, body=body).startswith("BLOCKED"), body)
        self.assertEqual(read_jsonl(config.OUTBOX_PATH), [])

    def test_normal_email_still_passes(self):
        self.assertTrue(self.email(self.make(), body="Launch moved to 15 October.").startswith("[MOCK]"))

    def test_payment_running_total_cap(self):
        fw = self.make()
        pay = lambda amt: fw.guard("make_payment", {"payee": "rent@upi", "amount": amt}, execute_tool)  # noqa: E731
        self.assertTrue(pay(400).startswith("[MOCK]"))
        self.assertTrue(pay(400).startswith("[MOCK]"))
        out = pay(300)                                   # 800 + 300 > 1000
        self.assertTrue(out.startswith("BLOCKED"))
        self.assertIn("total", out)
        self.assertEqual(sum(p["amount"] for p in read_jsonl(config.PAYMENTS_PATH)), 800.0)

    def test_payment_call_limit(self):
        fw = self.make()
        for _ in range(3):
            fw.guard("make_payment", {"payee": "rent@upi", "amount": 10}, execute_tool)
        out = fw.guard("make_payment", {"payee": "rent@upi", "amount": 10}, execute_tool)
        self.assertIn("call limit", out)

    def test_read_file_call_limit(self):
        fw = self.make()
        for _ in range(10):
            fw.guard("read_file", {"path": "notes/meeting_notes.txt"}, execute_tool)
        out = fw.guard("read_file", {"path": "notes/meeting_notes.txt"}, execute_tool)
        self.assertIn("call limit", out)

    def test_state_is_per_firewall_instance(self):
        a, b = self.make(), self.make()
        for _ in range(3):
            self.email(a)
        self.assertTrue(self.email(b).startswith("[MOCK]"))


class Phase4PolicyValidationTests(unittest.TestCase):
    def test_bad_phase4_values_rejected(self):
        bad = [
            {"max_calls": 0}, {"max_calls": "three"}, {"max_calls": 2.5}, {"max_calls": True},
            {"max_total_amount": -1}, {"max_body_chars": 0},
            {"blocked_body_patterns": "not-a-list"}, {"blocked_body_patterns": ["(unclosed"]},
        ]
        for rules in bad:
            with self.assertRaises(ValueError, msg=str(rules)):
                validate_policy({"tools": {"send_email": rules}})

    def test_phase3_policy_file_still_loads(self):
        policy = load_policy(config.BASE_DIR / "policies" / "policy_phase3.yaml")
        self.assertNotIn("max_calls", policy["tools"]["send_email"])
