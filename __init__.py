"""gateway_shield — KIN-282 egress audit (phase 1, OBSERVE ONLY).

Hermes calls hooks as hook(tool_name, **kwargs); the tool input is kwargs['args']
(a dict), e.g. terminal -> {'command': ...}, secure_web_reader -> {'url': ...},
brave_web_search -> {'query': ...}. post_tool_call also gets kwargs['result'].

Two hooks, both observe-only in phase 1:
  - pre_tool_call  → logs tool + target (command/url/query) and flags raw terminal
    network egress. Returns None (allow). Phase 2 will veto here.
  - post_tool_call → logs result size and whether the gateway verdict flagged an
    injection (audit of the judge's prod decisions).

stdlib only; output to stdout with `[gateway_shield]` prefix (greppable in logs).
"""

import json
import re

# Raw network from the shell (we already route web through the MCP gateway tools,
# so these tokens inside a `terminal` command mean a bypass attempt).
_NET_TOKEN = re.compile(
    r"\b(curl|wget|nc|ncat|telnet|aria2c|requests\.(get|post)|urllib|httpx|yt-dlp|youtube-dl|xurl)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|x-subscription-token:\s*\S+|api[_-]?key\s*[=:]\s*\S+|sk-[A-Za-z0-9_\-]{8,}|sk-or-[A-Za-z0-9_\-]{8,})"
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
        blob = _redact(_target(_tool_input(kwargs)))[:500]
        net = bool(_URL.search(blob)) or bool(_NET_TOKEN.search(blob))
        warn = "  <<<RAW_TERMINAL_EGRESS" if (tool_name == "terminal" and net) else ""
        print(f"[gateway_shield][audit-pre] tool={tool_name} net={net} target={blob!r}{warn}", flush=True)
    except Exception as e:  # never let auditing break a tool call
        print(f"[gateway_shield][audit-pre] hook_error={e!r}", flush=True)
    return None  # phase 1: observe only. phase 2 will block raw egress here.


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
    print("[gateway_shield] audit hooks registered (phase 1: observe-only)", flush=True)
