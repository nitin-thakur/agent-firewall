import tempfile
import unittest
from pathlib import Path

import config


class IsolatedLogsTestCase(unittest.TestCase):
    """Redirects all log/ledger files to a temp folder so tests never touch real logs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self._saved = (config.LOG_DIR, config.OUTBOX_PATH, config.PAYMENTS_PATH, config.AUDIT_PATH)
        config.LOG_DIR = tmp
        config.OUTBOX_PATH = tmp / "outbox.jsonl"
        config.PAYMENTS_PATH = tmp / "payments.jsonl"
        config.AUDIT_PATH = tmp / "audit.jsonl"

    def tearDown(self):
        (config.LOG_DIR, config.OUTBOX_PATH, config.PAYMENTS_PATH, config.AUDIT_PATH) = self._saved
        self._tmp.cleanup()
