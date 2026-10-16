"""Append-only audit log: every proposed tool call and the firewall's decision."""
from datetime import datetime, timezone

import config
from tools.storage import append_jsonl


def _trim(value, limit=500):
    if isinstance(value, dict):
        return {k: _trim(v, limit) for k, v in value.items()}
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "...[trimmed]"
    return value


class AuditLog:
    def __init__(self, path=None, run_id="run"):
        self.path = path
        self.run_id = run_id

    def log(self, tool, arguments, action, reason, rule="", approved=None):
        append_jsonl(self.path or config.AUDIT_PATH, {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "tool": tool,
            "arguments": _trim(arguments),
            "action": action,
            "reason": reason,
            "rule": rule,
            "approved": approved,
        })
