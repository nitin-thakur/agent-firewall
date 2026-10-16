from datetime import datetime, timezone

import config
from tools.file_tools import read_file
from tools.storage import append_jsonl


def send_email(to: str, subject: str = "", body: str = "", attachment_path: str = None) -> str:
    """MOCK email: nothing is ever sent. The message is only written to logs/outbox.jsonl."""
    if not isinstance(to, str) or "@" not in to:
        raise ValueError("'to' must be an email address")
    attachment_content = read_file(attachment_path) if attachment_path else None
    append_jsonl(config.OUTBOX_PATH, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "to": to,
        "subject": subject,
        "body": body,
        "attachment_path": attachment_path,
        "attachment_content": attachment_content,
        "mock": True,
    })
    return f"[MOCK] Email queued to {to} (no real email was sent)."
