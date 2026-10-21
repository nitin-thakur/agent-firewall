# Agent Firewall (Phases 1-7)

A middleware layer that sits between an LLM agent and its tools and decides **allow / ask / block**
for every tool call. 100% free: Python, open-source libraries, and an optional local model via Ollama.
All tools are **mocked** (no real email, no real money) and files are confined to `sandbox/`.

| Phase | What you get |
|---|---|
| 1 | Simple agent loop + 3 mock tools (`read_file`, `send_email`, `make_payment`) + Ollama wrapper |
| 2 | Attack demo: hidden instructions in `sandbox/inbox/*.txt` hijack an unprotected agent |
| 3 | Firewall: interception, YAML policy (allowlists, path rules, spending cap), JSON audit log, tests |
| 4 | Stateful limits (calls per run, total spend per run), email body size + secret-pattern checks, 2 new attacks that beat the Phase 3 rules |
| 5 | **Provenance tracking**: a recipient / payee / amount / file path that appears only in a file the agent read (not in your request) is held for approval. New attack that beats Phase 4, and a legitimate task that shows the cost |
| 6 | **Human approval prompt**: when the firewall asks, you see what the agent wants to do, why, and answer y/N (default No, fail-closed). Hard blocks can never be approved away |
| 7 | **Evaluation**: 30 attacks + 30 normal tasks x 7 defence setups, with a CSV and a written report. Includes 4 attacks designed to beat the firewall |

## Quick start (Windows 11 + VS Code)

1. Install **Python 3.12** from python.org (tick *Add Python to PATH*). Open this folder in VS Code.
2. Double-click `setup_windows.bat` (creates `.venv`, installs `pyyaml` and `ollama`).
3. Double-click `run_all_demos.bat`. You should see each attack SUCCEED with the firewall OFF and get STOPPED with it ON.
4. `run_tests.bat` runs the 124 unit tests. `run_eval.bat` runs the Phase 7 evaluation. `run_compare.bat` prints the Phase 3 / 4 / 5 / 6 comparison table.
5. VS Code: `Ctrl+Shift+P` -> *Python: Select Interpreter* -> pick `.venv`. Use *Run and Debug* for the ready-made launch configs.

The default `--llm mock` is a scripted, gullible agent: **no model, no internet, no GPU needed**. It is also
the right choice for reproducible evaluation numbers later.

## Using the real local model (optional, free)

1. Install Ollama from https://ollama.com and start it.
2. `ollama pull qwen2.5:7b` (or a lighter one: `ollama pull llama3.2:3b`, then `set OLLAMA_MODEL=llama3.2:3b`).
3. `.venv\Scripts\python.exe run_demo.py --scenario attack_exfil --llm ollama --firewall off`

Small local models do not always fall for the injection or may call tools inconsistently. That is normal;
try again or use the mock agent for guaranteed behaviour.

## Commands

```
python run_demo.py --all
python run_demo.py --scenario attack_exfil   --firewall off|on
python run_demo.py --scenario attack_payment --firewall off|on
python run_demo.py --scenario benign_summary --firewall on
python run_demo.py --scenario attack_exfil --llm ollama
python evaluate.py                              # Phase 7: 60 cases x 7 setups -> results/summary.md + results/cases.csv
python compare_policies.py                      # table: every scenario x (no firewall, Phase 3, 4, 5)
python run_demo.py --scenario attack_internal_leak --policy policies/policy_phase4.yaml   # Phase 4: leaks
python run_demo.py --scenario attack_internal_leak                                         # Phase 5: stopped
python run_demo.py --scenario benign_pay_bill                                              # Phase 6: asks YOU y/N in the terminal
python run_demo.py --scenario attack_internal_leak                                         # asks you about salaries.txt: type n
python run_demo.py --scenario attack_internal_leak --approve yes                          # what if the user wrongly says yes?
python run_demo.py --scenario attack_payment_loop --approve yes                           # even then: capped at Rs 800
python run_demo.py --scenario benign_pay_bill --approve no                                # auto-deny (what --all uses)
python run_demo.py --scenario attack_secret_in_body --policy policies/policy_phase3.yaml   # OLD rules: attack succeeds
python run_demo.py --scenario attack_secret_in_body                                          # Phase 4 rules: stopped
python run_demo.py --scenario attack_payment_loop --policy policies/policy_phase3.yaml     # OLD rules: Rs 1200 lost
python run_demo.py --scenario attack_payment_loop                                            # Phase 4 rules: limited to Rs 800
```

## Folder map

```
agent-firewall/
├── config.py               paths, model name, limits
├── run_demo.py             CLI entry point
├── runner.py               runs a scenario with/without firewall, prints what happened
├── requirements.txt        pyyaml, ollama
├── setup_windows.bat / run_all_demos.bat / run_tests.bat
├── agent/   agent.py (loop) · llm.py (ScriptedLLM + OllamaLLM)
├── tools/   file_tools · email_tools · payment_tools · registry · paths · storage
├── firewall/ engine.py (decisions) · provenance.py (where did a value come from?) · approval.py (y/N prompt) · policy.py · audit.py
├── policies/policy.yaml    the rules you edit (Phase 5)
├── policies/policy_phase3.yaml, policy_phase4.yaml   frozen older rules, for before/after comparison
├── compare_policies.py     runs every scenario under each policy and prints one table
├── evaluate.py             Phase 7: runs the full evaluation and writes results/
├── evaluation/             cases.py (30 attacks + 30 normal tasks as data) · harness.py (runs them) · report.py
├── results/                summary.md (the report) and cases.csv (one row per case x setup)
├── attacks/scenarios.py    benign + attack scenarios
├── sandbox/                FAKE files only (notes/, inbox/ with injections, secrets.txt)
├── logs/                   outbox.jsonl, payments.jsonl, audit.jsonl (created at run time)
├── tests/                  unittest suite (124 tests)
└── .vscode/                interpreter, test and debug settings
```

## How to experiment

- Edit `policies/policy.yaml` (e.g. add `boss@company.com` payees, change `max_amount`) and re-run.
- Add a new injection file in `sandbox/inbox/` and a scenario in `attacks/scenarios.py`.
- Read `logs/audit.jsonl` to see every proposed action, decision and reason.

## How provenance works (Phase 5)

The firewall keeps two kinds of text. **Trusted:** only what the user typed. **Untrusted:** the output of
`read_file` (outside content). Before a tool runs, each sensitive argument is traced:

| Where the value appears | Meaning | Default decision |
|---|---|---|
| in your request | you asked for it | normal rules apply |
| only in a file the agent read | likely injected | `ask` (you get a y/N prompt) |
| nowhere | the model made it up | `allow` (the allowlists still apply) |

Checks are boundary-aware text matching (so `evilboss@company.com` does not match `boss@company.com`).
When several checks fire, the **strictest** decision wins (block > ask > allow). Settings live in the
`provenance:` section of `policies/policy.yaml`.

## How the approval prompt works (Phase 6)

```
================================================================
  APPROVAL NEEDED - the firewall paused this action
================================================================
  The agent wants to: pay Rs 450 to electricity@upi
  You asked for:       "Read inbox/electricity_bill.txt and pay the bill."
  Why you are asked:   make_payment: payee 'electricity@upi' appears only in content the agent read (...)
  Only say yes if this is what YOU wanted. Doubt = No.
----------------------------------------------------------------
  Allow this action? [y/N]:
```

- **Fail closed:** only `y` / `yes` approves. Enter, `n`, garbage (after 3 tries), Ctrl+C, no keyboard, or an error in the
  approver all mean **no**. Run from a script/pipe and `run_demo.py` defaults to `--approve no`.
- **Hard blocks cannot be approved:** blocklists, allowlists, call limits and spend caps decide *before* anyone is asked.
  Only `ask` decisions (untrusted values, payments over `max_amount`) reach you. An approved call still counts toward limits.
- **The prompt is hardened:** values come from an agent an attacker may be steering, so control characters, newlines and
  invisible text-direction tricks are stripped and long values are truncated. A malicious address cannot fake a "-> APPROVED" line.
- **Every answer is audited** (`approved: true/false` in `logs/audit.jsonl`).
- `--approve yes` auto-approves **for demos only**: it shows what a careless user would let through.

## Evaluation results (Phase 7)

`python evaluate.py` runs **30 attack cases** and **30 normal tasks** under 7 defence setups with a scripted agent and writes
`results/summary.md` (the full report) and `results/cases.csv`. Each case runs in its own throw-away sandbox, so your real
files and logs are never touched, and results are identical on every run.

| Setup | Attacks succeeded | limited | stopped | Rs lost | Normal tasks completed | asked a question | hard-blocked |
|---|---|---|---|---|---|---|---|
| No firewall | 29/30 (97%) | 0 | 1 | 108378 | 30/30 | 0 | 0 |
| Phase 3 | 17/30 (57%) | 0 | 13 | 3180 | 26/30 | 1 | 3 |
| Phase 4 | 10/30 (33%) | 2 | 18 | 2150 | 23/30 | 1 | 6 |
| Phase 5 (questions denied) | 4/30 (13%) | 0 | 26 | 300 | 18/30 | 6 | 6 |
| Phase 6, careless user (always yes) | 10/30 (33%) | 2 | 18 | 2150 | 24/30 | 6 | 6 |
| Phase 6, careful user | 4/30 (13%) | 0 | 26 | 300 | 24/30 | 6 | 6 |
| Phase 6, careful + strict | 3/30 (10%) | 0 | 27 | 300 | 24/30 | 9 | 6 |

What the numbers say:

- **Each phase adds protection the previous one lacked.** Phase 3 stops attacks that use an outside address or a protected file;
  Phase 4 adds secrets in email bodies; Phase 5 adds the rest (leaks to *allowed* addresses, small or repeated payments to *allowed* payees, tampered amounts).
- **The 1 attack stopped with no firewall** is path traversal: the tool's own sandbox already blocks it.
- **A careless user cancels the Phase 5 benefit** (10/30, same as Phase 4): provenance only helps if the person reading the prompt says no.
- **Cost on normal tasks:** 6/30 (20%) need a question (value only in a file, or a payment above the cap), and 6/30 (20%) are blocked outright by
  this demo policy (outside email addresses, unlisted payees, call limits, regex false positives). Strict mode asks about 3 more.
- **4 attacks (A27 to A30) were written to beat the firewall and 3 still do** (4 without strict mode): duplicate payment using the user's own values,
  a phishing link or false statement inside an email body to a trusted recipient. The 4th (values spelled out so they appear nowhere literally)
  is stopped only by strict mode (`on_unknown_argument: ask`).

## Known limits (be honest about these in your write-up)

- **A careless "yes" defeats the human layer** (`P6: you YES` column: 3/5 attacks stopped instead of 5/5). The static
  limits still cap the damage, but the prompt is only as good as the person reading it. Each approval is per action;
  there is no "always allow", on purpose.
- **Approval fatigue:** `benign_pay_bill` shows that legitimate tasks also trigger prompts. Too many prompts train people to press `y`.
- **False positives:** a legitimate value that exists only in a file (`benign_pay_bill`: the payee and amount
  come from the bill) is held for approval too. Provenance cannot tell "you told it to pay the bill" from
  "the bill told it to pay". The human decides, via the Phase 6 prompt.
- **Email body text is not traced**, only recipient/attachment/payee/amount/path. Body checks are the Phase 4 regexes.
- **Only `read_file` output counts as untrusted.** If you add a web or email-reading tool, list it under
  `untrusted_tools`.
- **A value the model invents or obfuscates** (for example an address assembled from pieces) is "unknown" and
  passes provenance. Set `on_unknown_argument: ask` for stricter behaviour (more prompts), and rely on allowlists.
- **Regex secret detection** can still be evaded (Phase 4).
- **The attacks and the "gullible agent" are scripted by the same author as the firewall.** The Phase 7 numbers compare
  phases fairly, but they are not a security guarantee, and a real model may behave differently (see `results/summary.md`, section 7).

## Next phases

8. Write-up + demo video (README polish, threat model, related work, results). Optional: run a few attacks against a real Ollama model and report them separately

## Safety

Only run attacks against this test agent. Keep real files out of `sandbox/`. The secrets in it are fake.
