"""Phase 7: run the whole evaluation and write results/cases.csv and results/summary.md.

    python evaluate.py              # all 60 cases x 7 setups (takes a few seconds)
    python evaluate.py --out my_results
"""
import argparse
import sys
from pathlib import Path

import config
from evaluation import report
from evaluation.harness import run_all


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Agent firewall evaluation")
    ap.add_argument("--out", default=str(config.BASE_DIR / "results"), help="folder for cases.csv and summary.md")
    args = ap.parse_args()

    results = run_all()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report.write_csv(results, out / "cases.csv")
    (out / "summary.md").write_text(report.markdown(results), encoding="utf-8")
    print(report.console_table(results))
    print(f"\nWrote {out / 'cases.csv'} ({len(results)} rows) and {out / 'summary.md'}")


if __name__ == "__main__":
    main()
