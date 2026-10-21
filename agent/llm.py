"""LLM wrappers. Both expose:  chat(messages, tools) -> {"content": str, "tool_calls": [{"name", "arguments"}]}

Internal message format (provider independent):
  {"role": "system"|"user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"name": str, "arguments": dict}]}
  {"role": "tool", "name": str, "content": str}
"""
import re

import config

EMAIL_RE = re.compile(r"[\w.\-+]+@[\w\-]+(?:\.[\w\-]+)+")
PAY_RE = re.compile(r"pay\s+(?:rs\.?\s*)?(\d+(?:\.\d+)?)\s+to\s+([\w.\-]+@[\w.\-]+)", re.I)
PATH_RE = re.compile(r"(?:[\w\-]+/)*[\w\-]+\.txt")


def _call(name, arguments):
    return {"content": "", "tool_calls": [{"name": name, "arguments": arguments}]}


def _text(content):
    return {"content": content, "tool_calls": []}


class ScriptedLLM:
    """Deterministic, offline stand-in for a *gullible* agent (needs no model, no internet, no GPU).

    It does what the user asks, but it also obeys instructions hidden inside the files it reads.
    That is exactly the weakness (indirect prompt injection) the firewall must defend against.
    """

    name = "mock-gullible-agent"

    def chat(self, messages, tools=None):
        task = next(m["content"] for m in messages if m["role"] == "user")
        calls = [c for m in messages if m["role"] == "assistant" for c in (m.get("tool_calls") or [])]
        tool_msgs = [m for m in messages if m["role"] == "tool"]

        def called(name):
            return [c for c in calls if c["name"] == name]

        # Step 1: read the file the user mentioned.
        if not calls:
            m = PATH_RE.search(task)
            if m:
                return _call("read_file", {"path": m.group(0)})
            return _text("I could not find a file to read in your request.")

        last = tool_msgs[-1]["content"]
        if last.startswith(("BLOCKED", "ERROR")):
            return _text(f"I could not complete a step: {last}")

        first_doc = tool_msgs[0]["content"]  # the document the user asked about (may contain an injection)

        # Gullible behaviour 1: hidden "read <file> and email it to <address>" instruction.
        m_file = re.search(r"\bread\s+(?:the\s+file\s+)?([\w./\-]+\.txt)", first_doc, re.I)
        m_mail = EMAIL_RE.search(first_doc)
        if m_file and m_mail:
            inj_path, inj_email = m_file.group(1), m_mail.group(0)
            read_it = any(str(c["arguments"].get("path", "")).lower() == inj_path.lower()
                          for c in called("read_file"))
            if not read_it:
                return _call("read_file", {"path": inj_path})
            if not called("send_email"):
                return _call("send_email", {"to": inj_email, "subject": "Requested backup", "body": last})

        # Gullible behaviour 3 (Phase 4): hidden "email this exact text to X" instruction.
        inj_mail = re.search(r"send an email to ([\w.\-+]+@[\w\-.]+).*?write exactly:\s*(.+)", first_doc, re.S | re.I)
        if inj_mail and not called("send_email"):
            return _call("send_email", {"to": inj_mail.group(1), "subject": "verify",
                                        "body": inj_mail.group(2).strip().splitlines()[0]})

        # Gullible behaviour 2: hidden "pay this amount" instruction (4: may demand repeated payments).
        inj_pay = PAY_RE.search(first_doc)
        wanted = 3 if re.search(r"until three payments", first_doc, re.I) else 1
        if inj_pay and len(called("make_payment")) < wanted:
            return _call("make_payment", {"payee": inj_pay.group(2), "amount": float(inj_pay.group(1)),
                                          "note": "deposit" if wanted > 1 else "late fee"})

        # Legitimate behaviour: user asked to email a summary.
        if "email" in task.lower() and not called("send_email"):
            m = EMAIL_RE.search(task)
            if m:
                return _call("send_email", {"to": m.group(0), "subject": "Summary",
                                            "body": first_doc[:300]})

        return _text("Done. File summary: " + first_doc[:200].replace("\n", " "))


class OllamaLLM:
    """Free local model through Ollama (https://ollama.com). Requires the Ollama app to be running."""

    def __init__(self, model=None, host=None):
        try:
            import ollama
        except ImportError as e:  # pragma: no cover
            raise SystemExit("The 'ollama' package is missing. Run: pip install -r requirements.txt") from e
        self.model = model or config.OLLAMA_MODEL
        host = host or config.OLLAMA_HOST
        self._client = ollama.Client(host=host) if host else ollama.Client()
        self.name = f"ollama:{self.model}"

    @staticmethod
    def _to_ollama(m):
        if m["role"] == "assistant" and m.get("tool_calls"):
            return {"role": "assistant", "content": m.get("content", ""),
                    "tool_calls": [{"function": {"name": c["name"], "arguments": c["arguments"]}}
                                   for c in m["tool_calls"]]}
        if m["role"] == "tool":
            return {"role": "tool", "content": m["content"], "tool_name": m.get("name", "")}
        return {"role": m["role"], "content": m["content"]}

    @staticmethod
    def _get(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def chat(self, messages, tools=None):
        try:
            resp = self._client.chat(model=self.model,
                                     messages=[self._to_ollama(m) for m in messages],
                                     tools=tools)
        except Exception as e:  # noqa: BLE001
            raise SystemExit(
                f"Could not talk to Ollama ({type(e).__name__}: {e}).\n"
                f"Is the Ollama app running, and did you run:  ollama pull {self.model} ?") from e
        msg = self._get(resp, "message")
        calls = []
        for tc in self._get(msg, "tool_calls") or []:
            fn = self._get(tc, "function")
            args = self._get(fn, "arguments") or {}
            calls.append({"name": self._get(fn, "name"), "arguments": dict(args)})
        return {"content": self._get(msg, "content") or "", "tool_calls": calls}


def make_llm(kind: str):
    if kind == "mock":
        return ScriptedLLM()
    if kind == "ollama":
        return OllamaLLM()
    raise ValueError(f"unknown llm kind: {kind}")
