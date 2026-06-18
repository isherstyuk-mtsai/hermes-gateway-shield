"""gateway_shield — KIN-282 egress control (phase 2: BLOCK).

Hermes calls hooks as hook(tool_name, **kwargs); tool input is kwargs['args']
(a dict): terminal -> {'command': ...}, secure_web_reader -> {'url': ...}, etc.

pre_tool_call VETOES raw network egress from the `terminal` tool by returning
{"action": "block", "message": ...} — forcing the agent to fetch via the
sanitizing gateway tools (secure_web_reader / brave_web_search) instead. Local
shell work (parsing files, jq, python over already-fetched data) is untouched.
post_tool_call (observe-only) logs result size + whether the gateway flagged an
injection. All output to stdout with a `[gateway_shield]` prefix (Render logs).
"""

import json
import re

# Egress INTENT in a shell command → block. Fetch CLIs, python net libs, pip
# (package fetch), and direct fetch tools. Bare URLs alone do NOT block (a URL
# may just be printed/parsed); a fetch verb must be present.
_EGRESS = re.compile(
    r"(?ix)"
    r"\b(curl|wget|nc|ncat|telnet|aria2c|ftp|lynx|links|w3m|scp|sftp)\b"
    r"|\b(yt-dlp|youtube-dl|xurl)\b"
    r"|(urllib\.request|urlopen|\bhttpx\b|requests\.(get|post|put|patch|request)|aiohttp|socket\.create_connection)"
    r"|\b(pip|pip3)\s+install\b|python[0-9.]*\s+-m\s+pip\s+install"
)
_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|x-subscription-token:\s*\S+|api[_-]?key\s*[=:]\s*\S+|sk-[A-Za-z0-9_\-]{8,}|sk-or-[A-Za-z0-9_\-]{8,})"
)

_BLOCK_MSG = (
    "BLOCKED by gateway_shield (KIN-282): direct network egress from the terminal is not allowed. "
    "Fetch URLs with the `secure_web_reader` tool and search with `brave_web_search` — both sanitize "
    "the content and return an injection verdict. The terminal is for LOCAL processing only "
    "(parsing files in /tmp, jq/python over already-fetched data)."
)


def _redact(s):
    return _SECRET.sub("[REDACTED]", s)


def _tool_input(kwargs):
    ti = kwargs.get("args")
    return ti if isinstance(ti, dict) else {}


def _target(ti):
    for k in ("command", "cmd", "script", "input", "code"):
        if isinstance(ti.get(k), str):
            return ti[k]
    for k in ("url", "query"):
        if isinstance(ti.get(k), str):
            return ti[k]
    return json.dumps(ti, ensure_ascii=False) if ti else ""


def on_pre_tool_call(tool_name, **kwargs):
    try:
        blob = _target(_tool_input(kwargs))
        red = _redact(blob)[:500]
        if tool_name == "terminal" and _EGRESS.search(blob):
            print(f"[gateway_shield][BLOCK] tool=terminal raw egress denied: cmd={red!r}", flush=True)
            return {"action": "block", "message": _BLOCK_MSG}
        net = bool(_URL.search(blob)) or bool(_EGRESS.search(blob))
        print(f"[gateway_shield][audit-pre] tool={tool_name} net={net} target={red!r}", flush=True)
    except Exception as e:  # never let the guard break a tool call
        print(f"[gateway_shield][audit-pre] hook_error={e!r}", flush=True)
    return None  # allow


def on_post_tool_call(tool_name, **kwargs):
    try:
        result = kwargs.get("result")
        rlen = len(result) if isinstance(result, str) else -1
        flagged = isinstance(result, str) and '"injection":true' in result.replace(" ", "")
        note = "  INJECTION_FLAGGED" if flagged else ""
        print(f"[gateway_shield][audit-post] tool={tool_name} result_len={rlen}{note}", flush=True)
    except Exception as e:
        print(f"[gateway_shield][audit-post] hook_error={e!r}", flush=True)


def register(ctx):
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    print("[gateway_shield] hooks registered (phase 2: block raw terminal egress)", flush=True)
