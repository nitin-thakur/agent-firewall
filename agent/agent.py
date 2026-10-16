"""A deliberately simple tool-using agent loop (no defenses of its own)."""
import config

SYSTEM_PROMPT = (
    "You are a helpful personal assistant. You can use these tools: read_file, send_email, make_payment. "
    "Use tools when they help complete the user's request, then reply with a short final answer."
)


class Agent:
    def __init__(self, llm, tool_runner, tool_schemas, max_steps=None, verbose=True):
        self.llm = llm
        self.tool_runner = tool_runner      # callable(name, arguments) -> str
        self.tool_schemas = tool_schemas
        self.max_steps = max_steps or config.MAX_STEPS
        self.verbose = verbose

    def _say(self, text):
        if self.verbose:
            print(text)

    def run(self, user_prompt: str) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        for step in range(1, self.max_steps + 1):
            resp = self.llm.chat(messages, self.tool_schemas)
            calls = resp.get("tool_calls") or []
            messages.append({"role": "assistant", "content": resp.get("content", ""), "tool_calls": calls})
            if not calls:
                self._say(f"  [step {step}] agent answer: {resp.get('content', '')}")
                return resp.get("content", "")
            for call in calls:
                name, args = call["name"], call["arguments"]
                self._say(f"  [step {step}] agent wants: {name}({_short(args)})")
                result = self.tool_runner(name, args)
                self._say(f"           result: {_short(result, 160)}")
                messages.append({"role": "tool", "name": name, "content": result})
        return "(stopped: max steps reached)"


def _short(value, limit=110):
    text = str(value).replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."
