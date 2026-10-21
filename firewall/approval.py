"""Phase 6: human-in-the-loop approval.

When the firewall decides "ask", it calls an *approver*:  approver(tool, args, decision) -> bool.

Design rules (they matter for security):
  * Fail closed: anything other than a clear "yes" is a NO (Enter, EOF, garbage, errors, Ctrl+D).
  * The prompt shows the EXACT values the agent wants to use, in plain language, plus WHY you are being asked.
  * Values come from an attacker-influenced agent, so they are sanitised before display (control characters,
    newlines and invisible text-direction tricks are removed) and truncated, so they cannot fake a prompt.
  * Static blocks (blocklists, allowlists, caps) are never askable: only "ask" decisions reach the user.
"""
import sys
import unicodedata

MAX_VALUE_CHARS = 200
YES = {"y", "yes"}
NO = {"n", "no", ""}


def sanitize(value, limit=MAX_VALUE_CHARS) -> str:
    """Make an untrusted value safe to print: no control/format characters, one line, truncated."""
    text = str(value)
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\r\n\t":
            out.append(" ")
        elif cat in ("Cc", "Cf", "Cs", "Co", "Cn"):   # control, format (bidi tricks), surrogate, private, unassigned
            out.append("?")
        else:
            out.append(ch)
    clean = "".join(out).strip()
    return clean if len(clean) <= limit else clean[:limit] + "...[+%d chars]" % (len(clean) - limit)


def describe_action(tool: str, args: dict) -> str:
    """One plain-language sentence saying what the agent wants to do."""
    a = args if isinstance(args, dict) else {}
    if tool == "send_email":
        text = f"send an email to {sanitize(a.get('to'))}"
        if a.get("subject"):
            text += f" with subject '{sanitize(a.get('subject'), 80)}'"
        if a.get("attachment_path"):
            text += f", attaching the file '{sanitize(a.get('attachment_path'))}'"
        return text
    if tool == "make_payment":
        try:
            amount = f"Rs {float(a.get('amount')):g}"
        except (TypeError, ValueError):
            amount = f"an invalid amount ({sanitize(a.get('amount'), 40)})"
        return f"pay {amount} to {sanitize(a.get('payee'))}"
    if tool == "read_file":
        return f"read the file '{sanitize(a.get('path'))}'"
    return f"run '{sanitize(tool, 60)}' with {sanitize(a, 160)}"


def format_request(tool, args, decision, user_request=None) -> str:
    a = args if isinstance(args, dict) else {}
    lines = [
        "",
        "=" * 64,
        "  APPROVAL NEEDED - the firewall paused this action",
        "=" * 64,
        f"  The agent wants to: {describe_action(tool, a)}",
    ]
    if tool == "send_email" and a.get("body"):
        body = str(a["body"])
        lines.append(f"  Message starts with: \"{sanitize(body, 120)}\" ({len(body)} characters)")
    if user_request:
        lines.append(f"  You asked for:       \"{sanitize(user_request, 160)}\"")
    lines.append(f"  Why you are asked:   {sanitize(decision.reason, 400)}")
    lines.append("  Only say yes if this is what YOU wanted. Doubt = No.")
    lines.append("-" * 64)
    return "\n".join(lines)


class CliApprover:
    """Asks the person in the terminal. Default answer is NO.

    input_fn / output_fn are injectable so tests can run without a keyboard.
    """

    def __init__(self, user_request=None, input_fn=input, output_fn=print, max_attempts=3):
        self.user_request = user_request
        self.input_fn = input_fn
        self.output_fn = output_fn
        self.max_attempts = max_attempts
        self.history = []   # (tool, description, approved)

    def __call__(self, tool, args, decision) -> bool:
        self.output_fn(format_request(tool, args, decision, self.user_request))
        approved = self._ask()
        self.history.append((tool, describe_action(tool, args), approved))
        self.output_fn("  -> APPROVED by you." if approved else "  -> DENIED (the action will not run).")
        return approved

    def _ask(self) -> bool:
        for _ in range(self.max_attempts):
            try:
                answer = self.input_fn("  Allow this action? [y/N]: ")
            except (EOFError, KeyboardInterrupt):
                return False                      # no keyboard / Ctrl+C / Ctrl+D = deny
            answer = (answer or "").strip().lower()
            if answer in YES:
                return True
            if answer in NO:
                return False
            self.output_fn("  Please type y or n (Enter = no).")
        return False                              # too many invalid answers = deny


class FixedApprover:
    """Always answers the same way. 'yes' is for demos/tests; 'no' is the safe non-interactive default."""

    def __init__(self, answer: bool, user_request=None, output_fn=print):
        self.answer = bool(answer)
        self.user_request = user_request
        self.output_fn = output_fn
        self.history = []

    def __call__(self, tool, args, decision) -> bool:
        self.output_fn(format_request(tool, args, decision, self.user_request))
        self.output_fn(f"  -> {'APPROVED' if self.answer else 'DENIED'} automatically (demo mode, --approve "
                       f"{'yes' if self.answer else 'no'}).")
        self.history.append((tool, describe_action(tool, args), self.answer))
        return self.answer


def make_approver(mode, user_request=None):
    """mode: 'ask' (terminal prompt), 'yes' (auto-approve, demos only) or 'no' (auto-deny)."""
    if mode == "ask":
        return CliApprover(user_request)
    if mode == "yes":
        return FixedApprover(True, user_request)
    if mode == "no":
        return FixedApprover(False, user_request)
    raise ValueError(f"unknown approve mode: {mode}")


def default_mode() -> str:
    """Prompt when a person is at the keyboard; otherwise deny (e.g. when output is piped or in a scheduler)."""
    try:
        return "ask" if sys.stdin is not None and sys.stdin.isatty() else "no"
    except (AttributeError, ValueError):
        return "no"
