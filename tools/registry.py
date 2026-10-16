"""Tool registry: the functions, their LLM-facing schemas, and one safe executor."""
from tools.email_tools import send_email
from tools.file_tools import read_file
from tools.payment_tools import make_payment

TOOL_FUNCS = {
    "read_file": read_file,
    "send_email": send_email,
    "make_payment": make_payment,
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file from the user's sandbox folder.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Relative path, e.g. notes/todo.txt"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email, optionally attaching a sandbox file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email address"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "attachment_path": {"type": "string", "description": "Optional sandbox file to attach"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "make_payment",
            "description": "Pay money (in Indian rupees) to a payee.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payee": {"type": "string", "description": "Payee UPI id or account name"},
                    "amount": {"type": "number", "description": "Amount in rupees"},
                    "note": {"type": "string"},
                },
                "required": ["payee", "amount"],
            },
        },
    },
]


def execute_tool(name: str, arguments: dict) -> str:
    """Run a tool and always return a string (errors are returned, never raised)."""
    func = TOOL_FUNCS.get(name)
    if func is None:
        return f"ERROR: unknown tool '{name}'"
    if not isinstance(arguments, dict):
        arguments = {}
    try:
        return str(func(**arguments))
    except TypeError as e:
        return f"ERROR: bad arguments for {name}: {e}"
    except Exception as e:  # noqa: BLE001 - tool errors go back to the agent as text
        return f"ERROR: {type(e).__name__}: {e}"
