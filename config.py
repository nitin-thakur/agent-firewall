"""Central configuration. Paths are read at call time (config.X) so tests can override them."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = BASE_DIR / "sandbox"          # the ONLY folder the agent's tools may touch
LOG_DIR = BASE_DIR / "logs"
POLICY_PATH = BASE_DIR / "policies" / "policy.yaml"

OUTBOX_PATH = LOG_DIR / "outbox.jsonl"      # mock "sent" emails
PAYMENTS_PATH = LOG_DIR / "payments.jsonl"  # mock payments ledger
AUDIT_PATH = LOG_DIR / "audit.jsonl"        # firewall decisions

# Local free LLM via Ollama. Override with:  set OLLAMA_MODEL=llama3.2:3b
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST")  # None -> default http://localhost:11434

MAX_STEPS = 8          # max agent loop iterations
MAX_READ_CHARS = 4000  # max characters returned by read_file
