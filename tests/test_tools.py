import unittest

import config
from tests.base import IsolatedLogsTestCase
from tools.registry import execute_tool
from tools.storage import read_jsonl


class ToolTests(IsolatedLogsTestCase):
    def test_read_file_ok(self):
        out = execute_tool("read_file", {"path": "notes/meeting_notes.txt"})
        self.assertIn("Team meeting", out)

    def test_read_file_accepts_sandbox_prefix(self):
        out = execute_tool("read_file", {"path": "sandbox/notes/meeting_notes.txt"})
        self.assertIn("Team meeting", out)

    def test_read_file_blocks_path_traversal(self):
        for bad in ("../config.py", "..\\config.py", "/etc/passwd", "C:/Windows/win.ini"):
            self.assertTrue(execute_tool("read_file", {"path": bad}).startswith("ERROR"), bad)

    def test_send_email_is_mock_and_logged(self):
        out = execute_tool("send_email", {"to": "a@b.com", "subject": "s", "body": "b"})
        self.assertIn("MOCK", out)
        self.assertEqual(read_jsonl(config.OUTBOX_PATH)[0]["to"], "a@b.com")

    def test_send_email_with_attachment_stores_content(self):
        execute_tool("send_email", {"to": "a@b.com", "subject": "s", "body": "b",
                                    "attachment_path": "notes/meeting_notes.txt"})
        self.assertIn("Team meeting", read_jsonl(config.OUTBOX_PATH)[0]["attachment_content"])

    def test_payment_is_mock_and_logged(self):
        execute_tool("make_payment", {"payee": "x@upi", "amount": 10})
        self.assertEqual(read_jsonl(config.PAYMENTS_PATH)[0]["amount"], 10.0)

    def test_payment_rejects_bad_amount(self):
        self.assertTrue(execute_tool("make_payment", {"payee": "x@upi", "amount": -5}).startswith("ERROR"))

    def test_unknown_tool_and_bad_args(self):
        self.assertTrue(execute_tool("delete_everything", {}).startswith("ERROR"))
        self.assertTrue(execute_tool("read_file", {"wrong": 1}).startswith("ERROR"))


if __name__ == "__main__":
    unittest.main()
