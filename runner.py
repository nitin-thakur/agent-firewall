"""Runs one scenario end-to-end (with or without the firewall) and reports what happened."""
import os
import uuid
from dataclasses import dataclass, field

import config
from agent.agent import Agent
from agent.llm import make_llm
from attacks.scenarios import Scenario
from firewall.audit import AuditLog
from firewall.engine import Firewall
from firewall.policy import load_policy
from tools.registry import TOOL_SCHEMAS, execute_tool
from tools.storage import read_jsonl


@dataclass
class ScenarioResult:
    scenario: str
    firewall: bool
    answer: str
    emails: list = field(default_factory=list)
    payments: list = field(default_factory=list)
    success: bool = False     # attack succeeded (attacks) / task completed (benign)
    is_attack: bool = False

    @property
    def verdict(self) -> str:
        if self.is_attack:
            if self.success:
                return "ATTACK SUCCEEDED (bad)"
            lost = sum(p["amount"] for p in self.payments)
            if lost > 0:
                return f"attack LIMITED, not stopped: Rs {lost:g} still paid (partly bad)"
            if self.emails:
                return "attack LIMITED, not stopped: an email still went out (partly bad)"
            return "attack stopped (good)"
        return "task completed (good)" if self.success else "task FAILED (bad)"


def reset_runtime_state():
    for p in (config.OUTBOX_PATH, config.PAYMENTS_PATH):
        if os.path.exists(p):
            os.remove(p)


def run_scenario(scenario: Scenario, llm_kind="mock", firewall_on=True, verbose=True,
                 policy_path=None) -> ScenarioResult:
    reset_runtime_state()
    run_id = f"{scenario.name}-{uuid.uuid4().hex[:6]}"
    if firewall_on:
        fw = Firewall(load_policy(policy_path or config.POLICY_PATH), AuditLog(run_id=run_id))
        runner = lambda name, args: fw.guard(name, args, execute_tool)  # noqa: E731
    else:
        runner = execute_tool

    llm = make_llm(llm_kind)
    if verbose:
        print(f"\n=== {scenario.name} | firewall {'ON ' if firewall_on else 'OFF'} | llm: {llm.name} ===")
        print(f"  task: {scenario.prompt}")
    answer = Agent(llm, runner, TOOL_SCHEMAS, verbose=verbose).run(scenario.prompt)

    emails, payments = read_jsonl(config.OUTBOX_PATH), read_jsonl(config.PAYMENTS_PATH)
    result = ScenarioResult(scenario.name, firewall_on, answer, emails, payments,
                            scenario.success_check(emails, payments), scenario.is_attack)
    if verbose:
        print("  --- what actually happened ---")
        for e in emails:
            leaked = " (CONTAINS ATTACHED FILE CONTENT)" if e.get("attachment_content") else ""
            print(f"  EMAIL  -> {e['to']}{leaked}")
        for p in payments:
            print(f"  PAYMENT-> Rs {p['amount']:g} to {p['payee']}")
        if not emails and not payments:
            print("  (no emails sent, no payments made)")
        print(f"  VERDICT: {result.verdict}")
    return result
