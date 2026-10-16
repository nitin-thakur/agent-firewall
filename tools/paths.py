"""Sandbox path handling shared by the tools and the firewall."""
from pathlib import Path

import config


def resolve_in_sandbox(path: str) -> Path:
    """Resolve `path` inside the sandbox folder. Raises PermissionError if it escapes."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")
    p = path.strip().replace("\\", "/")
    if p.lower().startswith("sandbox/"):
        p = p[len("sandbox/"):]
    root = config.SANDBOX_DIR.resolve()
    target = (root / p).resolve()
    if target != root and root not in target.parents:
        raise PermissionError(f"Path '{path}' is outside the sandbox")
    return target
