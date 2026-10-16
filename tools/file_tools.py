import config
from tools.paths import resolve_in_sandbox


def read_file(path: str) -> str:
    """Read a text file from the sandbox folder."""
    target = resolve_in_sandbox(path)
    if not target.is_file():
        raise FileNotFoundError(f"No such file in sandbox: {path}")
    text = target.read_text(encoding="utf-8", errors="replace")
    if len(text) > config.MAX_READ_CHARS:
        text = text[: config.MAX_READ_CHARS] + "\n...[truncated]"
    return text
