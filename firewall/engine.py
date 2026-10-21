"""Firewall (Phase 3-5): intercept every tool call, decide allow / ask / block, log it.

Phase 4 adds per-run state (call counts, running payment total) and email body checks.
Phase 5 adds provenance: arguments that appear only in content the agent read (not in the user's
request) are escalated. When several checks fire, the STRICTEST decision wins (block > ask > allow).
"""
import fnmatch
import re
from dataclasses import dataclass

from firewall.audit import AuditLog
from firewall.provenance import LABELS, ProvenanceTracker
from tools.paths import resolve_in_sandbox


@dataclass
class Decision:
    action: str   # "allow" | "ask" | "block"
    reason: str
    rule: str = ""


def _allow(reason="passed all policy checks"):
    return Decision("allow", reason, "")


_SEVERITY = {"allow": 0, "ask": 1, "block": 2}


def _strictest(decisions):
    """Pick the strictest decision; on a tie the earliest one wins. Returns None for an empty list."""
    best = None
    for d in decisions:
        if d is not None and (best is None or _SEVERITY[d.action] > _SEVERITY[best.action]):
            best = d
    return best


def _matches(path: str, patterns) -> str:
    """Return the matching pattern (or '') for a sandbox-relative path."""
    norm = path.strip().replace("\\", "/").lstrip("/").lower()
    if norm.startswith("sandbox/"):
        norm = norm[len("sandbox/"):]
    base = norm.rsplit("/", 1)[-1]
    for pat in patterns or []:
        p = pat.lower()
        if fnmatch.fnmatch(base, p) or fnmatch.fnmatch(norm, p):
            return pat
    return ""


def _check_path(path, patterns, label):
    if not isinstance(path, str) or not path.strip():
        return Decision("block", f"{label}: missing or invalid path", "invalid_args")
    try:
        resolve_in_sandbox(path)
    except PermissionError:
        return Decision("block", f"{label}: path '{path}' is outside the sandbox", "sandbox")
    hit = _matches(path, patterns)
    if hit:
        return Decision("block", f"{label}: '{path}' matches protected pattern '{hit}'", "blocked_path_patterns")
    return None


class Firewall:
    def __init__(self, policy: dict, audit: AuditLog = None, approver=None):
        self.policy = policy
        self.audit = audit
        self.approver = approver  # Phase 6: callable(tool, args, decision) -> bool
        self.state = {}           # per-run counters: tool -> {"calls": int, "total": float}
        self.prov = ProvenanceTracker(policy.get("provenance"))   # Phase 5
        self.decisions = []       # (tool, action, rule, approved) for every guarded call

    # ---------- Phase 5: provenance ----------
    def set_user_request(self, text: str) -> None:
        """Tell the firewall what the USER actually asked for (the only trusted text)."""
        self.prov.set_user_request(text)

    def observe(self, tool: str, args: dict, result) -> None:
        """Record outside content that entered the agent's context (e.g. the text of a file it read)."""
        if not self.prov.enabled or tool not in self.prov.untrusted_tools or not isinstance(result, str):
            return
        if result.startswith(("ERROR", "BLOCKED")):
            return
        source = (args or {}).get("path") or tool
        self.prov.add_untrusted(source, result)

    def _check_provenance(self, tool, args):
        if not self.prov.enabled:
            return None
        found = []
        for name in self.prov.checked_args.get(tool, []):
            status, source = self.prov.classify(name, args.get(name))
            label = LABELS.get(name, name)
            value = args.get(name)
            if status == "untrusted" and self.prov.on_untrusted != "allow":
                found.append(Decision(
                    self.prov.on_untrusted,
                    f"{tool}: {label} '{value}' appears only in content the agent read ({source}), "
                    f"not in your request - possible prompt injection", "provenance"))
            elif status == "unknown" and self.prov.on_unknown != "allow":
                found.append(Decision(
                    self.prov.on_unknown,
                    f"{tool}: {label} '{value}' does not come from your request or from anything "
                    f"the agent read", "provenance_unknown"))
        return _strictest(found)

    def _st(self, tool):
        return self.state.setdefault(tool, {"calls": 0, "total": 0.0})

    def _record(self, tool, args):
        """Count a call that was actually allowed to run."""
        st = self._st(tool)
        st["calls"] += 1
        if tool == "make_payment":
            try:
                st["total"] += float(args.get("amount"))
            except (TypeError, ValueError):
                pass

    # ---------- decision logic ----------
    def evaluate(self, tool: str, args: dict) -> Decision:
        args = args if isinstance(args, dict) else {}
        rules = self.policy["tools"].get(tool)
        if rules is None:
            return Decision(self.policy["default_action"], f"tool '{tool}' is not in the policy", "default_action")
        action = rules.get("action", "block")
        if action == "block":
            return Decision("block", f"tool '{tool}' is disabled by policy", "tool_action")

        candidates = []
        checker = getattr(self, f"_check_{tool}", None)
        if checker:
            candidates.append(checker(args, rules))
        max_calls = rules.get("max_calls")
        if max_calls is not None and self._st(tool)["calls"] >= max_calls:
            candidates.append(Decision("block", f"{tool}: call limit reached ({max_calls} per run)", "max_calls"))
        candidates.append(self._check_provenance(tool, args))
        if action == "ask":
            candidates.append(Decision("ask", f"tool '{tool}' always requires approval", "tool_action"))
        return _strictest(candidates) or _allow()

    def _check_read_file(self, args, rules):
        return _check_path(args.get("path"), rules.get("blocked_path_patterns"), "read_file")

    def _check_send_email(self, args, rules):
        to = args.get("to")
        if not isinstance(to, str) or "@" not in to:
            return Decision("block", "send_email: missing or invalid recipient", "invalid_args")
        domain = to.rsplit("@", 1)[-1].strip().lower()
        allowed = [d.lower() for d in rules.get("allowed_recipient_domains") or []]
        if allowed and not any(domain == d or domain.endswith("." + d) for d in allowed):
            return Decision("block", f"send_email: recipient domain '{domain}' is not on the allowlist",
                            "allowed_recipient_domains")
        if args.get("attachment_path"):
            problem = _check_path(args["attachment_path"], rules.get("blocked_attachment_patterns"),
                                  "send_email attachment")
            if problem:
                return problem
        body = str(args.get("body") or "")
        max_chars = rules.get("max_body_chars")
        if max_chars is not None and len(body) > max_chars:
            return Decision("block", f"send_email: body is {len(body)} characters (limit {max_chars})",
                            "max_body_chars")
        text = f"{args.get('subject') or ''}\n{body}"
        for pattern in rules.get("blocked_body_patterns") or []:
            if re.search(pattern, text, re.I):
                return Decision("block", f"send_email: message looks like it contains sensitive data "
                                         f"(matched '{pattern}')", "blocked_body_patterns")
        return None

    def _check_make_payment(self, args, rules):
        try:
            amount = float(args.get("amount"))
        except (TypeError, ValueError):
            return Decision("block", "make_payment: missing or invalid amount", "invalid_args")
        payee = args.get("payee")
        if not isinstance(payee, str) or not payee.strip():
            return Decision("block", "make_payment: missing payee", "invalid_args")
        payees = [p.lower() for p in rules.get("allowed_payees") or []]
        if payees and payee.strip().lower() not in payees:
            return Decision("block", f"make_payment: payee '{payee}' is not on the allowlist", "allowed_payees")
        total_cap = rules.get("max_total_amount")
        spent = self._st("make_payment")["total"]
        if total_cap is not None and spent + amount > float(total_cap):
            return Decision("block", f"make_payment: Rs {amount:g} would bring this run's total to "
                                     f"Rs {spent + amount:g} (limit Rs {float(total_cap):g})", "max_total_amount")
        limit = rules.get("max_amount")
        if limit is not None and amount > float(limit):
            return Decision("ask", f"make_payment: Rs {amount:g} is above the Rs {float(limit):g} limit", "max_amount")
        return None

    # ---------- enforcement ----------
    def guard(self, tool: str, args: dict, execute) -> str:
        """Evaluate, log, and only run `execute(tool, args)` if allowed."""
        decision = self.evaluate(tool, args)
        approved = None
        if decision.action == "ask" and self.approver is not None:
            try:
                approved = self.approver(tool, args, decision) is True   # only a real True counts
            except Exception as e:  # noqa: BLE001 - fail closed: an approver error is a "no"
                approved = False
                decision = Decision("ask", f"{decision.reason} [approver failed: {type(e).__name__}; treated as no]",
                                    decision.rule)

        if self.audit:
            self.audit.log(tool, args, decision.action, decision.reason, decision.rule, approved)
        self.decisions.append((tool, decision.action, decision.rule, approved))

        if decision.action == "allow" or approved:
            self._record(tool, args)
            result = execute(tool, args)
            self.observe(tool, args, result)
            return result
        if decision.action == "ask":
            if self.approver is None:
                return f"BLOCKED by firewall (needs user approval, but no approver is configured): {decision.reason}"
            return f"BLOCKED by firewall (you denied this action): {decision.reason}"
        return f"BLOCKED by firewall: {decision.reason}"
