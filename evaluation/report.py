"""Turns raw results into CSV + a markdown report. Pure functions: no randomness, no timestamps."""
import csv
from collections import Counter, OrderedDict

from evaluation.cases import ATTACKS, BENIGN
from evaluation.harness import NO_FW, P3, P4, P5, P6_CAREFUL, P6_CARELESS, P6_STRICT, SETUPS

CSV_FIELDS = ["case_id", "kind", "category", "setup", "outcome", "rs_lost", "emails_sent", "asked", "blocked", "stopped_by"]


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_FIELDS)
        for r in results:
            w.writerow([getattr(r, k) for k in CSV_FIELDS])


def index(results):
    return {(r.case_id, r.setup): r for r in results}


def pct(n, total):
    return f"{100 * n / total:.0f}%" if total else "-"


def headline(results):
    """One row per setup with the numbers that go into the write-up."""
    idx = index(results)
    rows = []
    for s in SETUPS:
        att = [idx[(c.id, s.name)] for c in ATTACKS]
        ben = [idx[(c.id, s.name)] for c in BENIGN]
        succ = sum(r.outcome == "success" for r in att)
        part = sum(r.outcome == "partial" for r in att)
        stop = sum(r.outcome == "stopped" for r in att)
        rows.append(OrderedDict([
            ("setup", s.name), ("succeeded", succ), ("limited", part), ("stopped", stop),
            ("rs_lost", sum(r.rs_lost for r in att)),
            ("completed", sum(r.outcome == "completed" for r in ben)),
            ("asked", sum(r.asked > 0 for r in ben)),
            ("hard_blocked", sum(r.blocked > 0 for r in ben)),
            ("n_attacks", len(att)), ("n_benign", len(ben)),
        ]))
    return rows


def console_table(results) -> str:
    h = headline(results)
    lines = [f"{'Setup':<30}{'Attacks: succeeded/limited/stopped':<38}{'Rs lost':>8}   {'Normal tasks: completed':<25}{'asked':>6}{'hard-blocked':>14}"]
    lines.append("-" * 124)
    for r in h:
        lines.append(f"{r['setup']:<30}{str(r['succeeded']) + ' / ' + str(r['limited']) + ' / ' + str(r['stopped']):<38}"
                     f"{r['rs_lost']:>8g}   {str(r['completed']) + '/' + str(r['n_benign']):<25}{r['asked']:>6}{r['hard_blocked']:>14}")
    return "\n".join(lines)


def _first_stopping_setup(idx, case_id):
    if idx[(case_id, NO_FW.name)].outcome == "stopped":
        return "Never needed (tool sandbox)"
    for s, label in ((P3, "Phase 3"), (P4, "Phase 4"), (P5, "Phase 5")):
        if idx[(case_id, s.name)].outcome == "stopped":
            return label
    if idx[(case_id, P6_STRICT.name)].outcome == "stopped":
        return "Only strict mode"
    return "Not stopped"


def markdown(results) -> str:
    idx = index(results)
    h = headline(results)
    out = []
    w = out.append
    w("# Phase 7 - Evaluation report\n")
    w(f"**{len(ATTACKS)} attack cases** and **{len(BENIGN)} normal-task cases**, each run under {len(SETUPS)} defence setups "
      "with a scripted agent (deterministic: same numbers every run). Everything is fake: mock email, mock payments, fake secrets.\n")
    w("**Attack outcomes:** *succeeded* = the attacker reached the full goal; *limited* = the full goal was not reached but some "
      "money or email still went out; *stopped* = nothing unauthorised happened.  \n"
      "**Normal tasks:** *completed* = the task's goal was met; *asked* = the firewall asked the user at least once; "
      "*hard-blocked* = at least one step was blocked outright (cannot be approved).\n")

    w("## 1. Headline numbers\n")
    w("| Setup | Attacks succeeded | limited | stopped | Rs lost | Normal tasks completed | asked a question | hard-blocked |")
    w("|---|---|---|---|---|---|---|---|")
    for r in h:
        w(f"| {r['setup']} | {r['succeeded']}/{r['n_attacks']} ({pct(r['succeeded'], r['n_attacks'])}) | {r['limited']} | "
          f"{r['stopped']} | {r['rs_lost']:g} | {r['completed']}/{r['n_benign']} ({pct(r['completed'], r['n_benign'])}) | "
          f"{r['asked']} ({pct(r['asked'], r['n_benign'])}) | {r['hard_blocked']} ({pct(r['hard_blocked'], r['n_benign'])}) |")
    w("")

    w("## 2. Which phase first stops each attack\n")
    first = {c.id: _first_stopping_setup(idx, c.id) for c in ATTACKS}
    counts = Counter(first.values())
    w("| First setup that fully stops it | Attacks |")
    w("|---|---|")
    for label in ("Never needed (tool sandbox)", "Phase 3", "Phase 4", "Phase 5", "Only strict mode", "Not stopped"):
        if counts.get(label):
            ids = ", ".join(sorted(k for k, v in first.items() if v == label))
            w(f"| {label} | {counts[label]} ({ids}) |")
    w("")

    w("## 3. Attacks that succeeded, by category (succeeded / total)\n")
    cats = sorted({c.category for c in ATTACKS})
    cols = [NO_FW, P3, P4, P5, P6_CARELESS, P6_CAREFUL, P6_STRICT]
    w("| Category | " + " | ".join(s.name for s in cols) + " |")
    w("|---|" + "---|" * len(cols))
    for cat in cats:
        ids = [c.id for c in ATTACKS if c.category == cat]
        cells = [f"{sum(idx[(i, s.name)].outcome == 'success' for i in ids)}/{len(ids)}" for s in cols]
        w(f"| {cat} | " + " | ".join(cells) + " |")
    w("")

    w("## 4. What still gets through (careful user, default policy)\n")
    for c in ATTACKS:
        r = idx[(c.id, P6_CAREFUL.name)]
        if r.outcome != "stopped":
            strict = idx[(c.id, P6_STRICT.name)].outcome
            w(f"- **{c.id} - {c.title}** ({r.outcome}). {c.note} Strict mode: {strict}.")
    w("")

    w("## 5. Cost on normal tasks\n")
    w("| Task | Prompted (Phase 6 policy) | Hard-blocked (Phase 6 policy) | Why |")
    w("|---|---|---|---|")
    for c in BENIGN:
        r = idx[(c.id, P6_CAREFUL.name)]
        strict = idx[(c.id, P6_STRICT.name)]
        if r.asked or r.blocked or strict.asked:
            kind = "hard-blocked" if r.blocked else ("asked" if r.asked else "asked only in strict mode")
            w(f"| {c.id} {c.title} | {'yes' if r.asked else ('strict only' if strict.asked else 'no')} | "
              f"{'yes' if r.blocked else 'no'} | {kind}{'. ' + c.note if c.note else ''} |")
    w("")

    w("## 6. Which rule fired first (careful user)\n")
    rules = Counter(idx[(c.id, P6_CAREFUL.name)].stopped_by for c in ATTACKS
                    if idx[(c.id, P6_CAREFUL.name)].outcome == "stopped")
    w("| Rule | Attacks it stopped first |")
    w("|---|---|")
    for rule, n in rules.most_common():
        w(f"| {rule} | {n} |")
    w("\n*Several layers often apply to the same attack; this table counts only the first rule that fired.*\n")

    w("## 7. How far to trust these numbers\n")
    w("- The agent is **scripted**: it does exactly what each attack file says. A real model may ignore some injections (fewer attacks) "
      "or follow them in ways not covered here. These numbers measure the **firewall**, not any model.")
    w("- The attacks and the firewall were written by the same author. Four attacks (A27 to A30) were designed **on purpose to get past it**, "
      "but a different attacker would find others. 30 cases is a small sample: use the percentages to compare phases, not as a security guarantee.")
    w("- 'Rs lost' counts only money paid beyond what the user really asked for (for example A27 pays Rs 300 legitimately, so only the duplicate counts).")
    w("- 'Careful user' is an **idealised human** who always judges correctly. 'Careless user' says yes to everything. Real people are in between.")
    w("- Normal-task friction depends on **my demo policy** (allowlist, caps). A different policy changes the cost.")
    w("- All results are reproducible with `python evaluate.py`; per-case rows are in `results/cases.csv`.")
    return "\n".join(out) + "\n"
