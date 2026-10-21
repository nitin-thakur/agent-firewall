"""Phase 5: provenance tracking.

Question answered for every sensitive argument (recipient, payee, amount, file path):
    "Where did this value come from?"

  trusted    - it appears in the USER's own request
  untrusted  - it does NOT appear in the user's request, but it DOES appear in content the agent read
               from outside (for example a file in inbox/). That is the signature of prompt injection.
  unknown    - it appears in neither (the model produced it itself)

Matching is deliberately simple and explainable (boundary-aware text search), not machine learning.
"""
import re

DEFAULT_UNTRUSTED_TOOLS = ["read_file"]
DEFAULT_CHECKED_ARGS = {
    "read_file": ["path"],
    "send_email": ["to", "attachment_path"],
    "make_payment": ["payee", "amount"],
}
LABELS = {
    "to": "recipient",
    "payee": "payee",
    "amount": "amount",
    "path": "file path",
    "attachment_path": "attachment",
}
PATH_ARGS = {"path", "attachment_path"}
NUMBER_ARGS = {"amount"}


def normalize_text(text) -> str:
    """Lower-case, forward slashes, and drop the optional 'sandbox/' prefix."""
    return str(text).lower().replace("\\", "/").replace("sandbox/", "")


def _has_word(haystack: str, needle: str) -> bool:
    """True if `needle` occurs in `haystack` as a whole token (not inside a longer address or path)."""
    needle = needle.strip()
    if not needle:
        return False
    pattern = r"(?<![\w.+/-])" + re.escape(needle) + r"(?![\w-]|\.\w)"
    return re.search(pattern, haystack) is not None


def _has_number(haystack: str, value) -> bool:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    digits = format(number, "f").rstrip("0").rstrip(".") or "0"
    text = re.sub(r"(?<=\d),(?=\d)", "", haystack)  # 1,200 -> 1200
    pattern = r"(?<!\d)(?<!\d\.)" + re.escape(digits) + r"(?:\.0+)?(?!\d|\.\d)"
    return re.search(pattern, text) is not None


def _appears(arg_name: str, value, haystack: str) -> bool:
    """Does this argument value occur in the (already normalized) text?"""
    if arg_name in NUMBER_ARGS:
        return _has_number(haystack, value)
    needle = normalize_text(value).strip().lstrip("/")
    if arg_name in PATH_ARGS:
        if _has_word(haystack, needle):
            return True
        base = needle.rsplit("/", 1)[-1]          # the agent may drop the folder name
        return base != needle and _has_word(haystack, base)
    return _has_word(haystack, needle)


class ProvenanceTracker:
    def __init__(self, settings=None):
        settings = settings or {}
        self.enabled = bool(settings) and settings.get("enabled", True)
        self.untrusted_tools = list(settings.get("untrusted_tools", DEFAULT_UNTRUSTED_TOOLS))
        self.checked_args = settings.get("checked_args", DEFAULT_CHECKED_ARGS)
        self.on_untrusted = settings.get("on_untrusted_argument", "ask")
        self.on_unknown = settings.get("on_unknown_argument", "allow")
        self.user_text = ""
        self.untrusted = []   # list of (source label, normalized text)

    def set_user_request(self, text: str) -> None:
        self.user_text = normalize_text(text or "")

    def add_untrusted(self, source: str, text: str) -> None:
        self.untrusted.append((str(source), normalize_text(text)))

    def classify(self, arg_name: str, value):
        """Return (status, source) where status is 'trusted' | 'untrusted' | 'unknown' | 'skip'."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return "skip", None
        if _appears(arg_name, value, self.user_text):
            return "trusted", None
        for source, text in self.untrusted:
            if _appears(arg_name, value, text):
                return "untrusted", source
        return "unknown", None
