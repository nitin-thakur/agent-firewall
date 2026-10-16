"""Command-line demo.

Examples (from the project folder, with the venv active or via .venv\\Scripts\\python):
  python run_demo.py --all                                   # every scenario, firewall OFF then ON (offline mock agent)
  python run_demo.py --scenario attack_exfil --firewall off  # watch the attack succeed
  python run_demo.py --scenario attack_exfil --firewall on   # watch the firewall stop it
  python run_demo.py --scenario attack_exfil --llm ollama    # use the real local model
  python run_demo.py --all --policy policies/policy_phase3.yaml   # compare with the old Phase 3 rules
"""
import argparse
import sys

from attacks.scenarios import SCENARIOS
from runner import run_scenario


def main():
    if hasattr(sys.stdout, "reconfigure"):  # avoid Windows console encoding errors
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="Agent firewall demo")
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), default="attack_exfil")
    ap.add_argument("--llm", choices=["mock", "ollama"], default="mock")
    ap.add_argument("--firewall", choices=["on", "off"], default="on")
    ap.add_argument("--policy", default=None, help="path to a policy YAML (default: policies/policy.yaml)")
    ap.add_argument("--all", action="store_true", help="run every scenario with firewall off and on")
    args = ap.parse_args()

    if args.all:
        rows = []
        for name, sc in SCENARIOS.items():
            for fw in (False, True):
                rows.append(run_scenario(sc, args.llm, fw, verbose=True, policy_path=args.policy))
        print("\n" + "=" * 78)
        print(f"{'scenario':<24}{'firewall':<10}{'result'}")
        print("-" * 100)
        for r in rows:
            print(f"{r.scenario:<24}{'ON' if r.firewall else 'OFF':<10}{r.verdict}")
        print("=" * 78)
        print("Audit log of firewall decisions: logs/audit.jsonl")
    else:
        run_scenario(SCENARIOS[args.scenario], args.llm, args.firewall == "on", verbose=True,
                     policy_path=args.policy)


if __name__ == "__main__":
    main()
