# Agent Firewall (Phases 1-6)

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

## Quick start (Windows 11 + VS Code)

1. Install **Python 3.12** from python.org (tick *Add Python to PATH*). Open this folder in VS Code.
2. Double-click `setup_windows.bat` (creates `.venv`, installs `pyyaml` and `ollama`).
3. Double-click `run_all_demos.bat`. You should see each attack SUCCEED with the firewall OFF and get STOPPED with it ON.
4. `run_tests.bat` runs the 98 unit tests. `run_compare.bat` prints the Phase 3 / 4 / 5 / 6 comparison table.
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
├── attacks/scenarios.py    benign + attack scenarios
├── sandbox/                FAKE files only (notes/, inbox/ with injections, secrets.txt)
├── logs/                   outbox.jsonl, payments.jsonl, audit.jsonl (created at run time)
├── tests/                  unittest suite (98 tests)
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
- **The attacks and the "gullible agent" are scripted by me,** so 5/5 shows the mechanism works, not that it
  resists a real attacker. Week 7 evaluation (many varied cases, a real model) is where this is tested properly.

## Next phases

7. Evaluation set (20-30 attacks, 20-30 normal tasks) · 8. Write-up + demo video

## Safety

Only run attacks against this test agent. Keep real files out of `sandbox/`. The secrets in it are fake.
