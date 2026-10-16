from datetime import datetime, timezone

import config
from tools.storage import append_jsonl


def make_payment(payee: str, amount: float, note: str = "") -> str:
    """MOCK payment: no money moves. The payment is only written to logs/payments.jsonl."""
    amount = float(amount)
    if amount <= 0:
        raise ValueError("amount must be positive")
    if not isinstance(payee, str) or not payee.strip():
        raise ValueError("payee must be a non-empty string")
    append_jsonl(config.PAYMENTS_PATH, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "payee": payee,
        "amount": amount,
        "note": note,
        "mock": True,
    })
    return f"[MOCK] Payment of Rs {amount:g} to {payee} recorded (no real money moved)."
