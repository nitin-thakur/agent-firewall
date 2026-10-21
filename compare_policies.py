"""Runs every scenario under each defence level (mock agent) and prints one comparison table.

    python compare_policies.py

Columns:
  no firewall   nothing in the way
  Phase 3       static allowlists / blocklists
  Phase 4       + call limits, spend cap, email body checks
  Phase 5       + provenance (questions are held; nobody answers them)
  P6: you NO    Phase 5 rules + a careful user who denies every approval request
  P6: you YES   Phase 5 rules + a careless user who approves every approval request
"""
import io
import sys
from contextlib import redirect_stdout

import config
from attacks.scenarios import SCENARIOS
from runner import run_scenario

P = config.BASE_DIR / "policies"
COLUMNS = [   # (title, firewall on?, policy file, approve mode)
    ("no firewall", False, None, None),
    ("Phase 3", True, P / "policy_phase3.yaml", None),
    ("Phase 4", True, P / "policy_phase4.yaml", None),
    ("Phase 5", True, config.POLICY_PATH, None),
    ("P6: you NO", True, config.POLICY_PATH, "no"),
    ("P6: you YES", True, config.POLICY_PATH, "yes"),
]
W0, W = 24, 22


def cell(r) -> str:
    damage = sum(p["amount"] for p in r.payments)
    if r.is_attack:
        if r.success:
            return "SUCCEEDED"
        if damage > 0:
            return f"limited (Rs {damage:g})"
        if r.emails:
            return "limited (email sent)"
        return "stopped"
    if r.success:
        return "done"
    if r.asked:
        return "needs approval"
    return "you denied" if r.denied else "FAILED"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(f"{'scenario':<{W0}}" + "".join(f"{c[0]:<{W}}" for c in COLUMNS))
    print("-" * (W0 + W * len(COLUMNS)))
    stopped = {c[0]: 0 for c in COLUMNS}
    attacks = 0
    for sc in SCENARIOS.values():
        attacks += sc.is_attack
        row = f"{sc.name:<{W0}}"
        for title, fw_on, policy, mode in COLUMNS:
            with redirect_stdout(io.StringIO()):          # hide the approval prompts
                r = run_scenario(sc, "mock", fw_on, verbose=False, policy_path=policy, approve_mode=mode)
            row += f"{cell(r):<{W}}"
            if sc.is_attack and not r.emails and not r.payments:
                stopped[title] += 1
        print(row)
    print("-" * (W0 + W * len(COLUMNS)))
    print(f"{'attacks fully stopped':<{W0}}" + "".join(f"{str(stopped[c[0]]) + '/' + str(attacks):<{W}}" for c in COLUMNS))


if __name__ == "__main__":
    main()
