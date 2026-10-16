# Agent Firewall (Phases 1-4)

A middleware layer that sits between an LLM agent and its tools and decides **allow / ask / block**
for every tool call. 100% free: Python, open-source libraries, and an optional local model via Ollama.
All tools are **mocked** (no real email, no real money) and files are confined to `sandbox/`.

| Phase | What you get |
|---|---|
| 1 | Simple agent loop + 3 mock tools (`read_file`, `send_email`, `make_payment`) + Ollama wrapper |
| 2 | Attack demo: hidden instructions in `sandbox/inbox/*.txt` hijack an unprotected agent |
| 3 | Firewall: interception, YAML policy (allowlists, path rules, spending cap), JSON audit log, tests |
| 4 | Stateful limits (calls per run, total spend per run), email body size + secret-pattern checks, 2 new attacks that beat the Phase 3 rules |

## Quick start (Windows 11 + VS Code)

1. Install **Python 3.12** from python.org (tick *Add Python to PATH*). Open this folder in VS Code.
2. Double-click `setup_windows.bat` (creates `.venv`, installs `pyyaml` and `ollama`).
3. Double-click `run_all_demos.bat`. You should see each attack SUCCEED with the firewall OFF and get STOPPED with it ON.
4. `run_tests.bat` runs the 37 unit tests.
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
├── firewall/ engine.py (decisions) · policy.py (YAML load/validate) · audit.py (JSONL log)
├── policies/policy.yaml    the rules you edit (Phase 4)
├── policies/policy_phase3.yaml  frozen Phase 3 rules, for before/after comparison
├── attacks/scenarios.py    benign + attack scenarios
├── sandbox/                FAKE files only (notes/, inbox/ with injections, secrets.txt)
├── logs/                   outbox.jsonl, payments.jsonl, audit.jsonl (created at run time)
├── tests/                  unittest suite (37 tests)
└── .vscode/                interpreter, test and debug settings
```

## How to experiment

- Edit `policies/policy.yaml` (e.g. add `boss@company.com` payees, change `max_amount`) and re-run.
- Add a new injection file in `sandbox/inbox/` and a scenario in `attacks/scenarios.py`.
- Read `logs/audit.jsonl` to see every proposed action, decision and reason.

## Known limits of Phase 4 (on purpose)

- Rules are still static. The firewall does not know *where* an argument came from, so the first payments
  to an allowed payee still go through (`attack_payment_loop` loses Rs 800 even with the firewall ON).
  Phase 5 (provenance tracking) is designed to close exactly this gap.
- Secret detection is regex-based and can be evaded (e.g. text split or encoded). It is a safety net, not a guarantee.
- `ask` currently behaves like `block` (the `approver` hook exists for Phase 6).

## Next phases

5. Provenance/taint tracking ("this recipient came from an untrusted file, not the user")
6. Human-readable approval prompt · 7. Evaluation set (20-30 attacks, 20-30 normal tasks) · 8. Write-up + demo video

## Safety

Only run attacks against this test agent. Keep real files out of `sandbox/`. The secrets in it are fake.
