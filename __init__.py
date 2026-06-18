"""gateway_shield — KIN-282 egress audit (phase 1).

Phase 1 = OBSERVE ONLY. Two hooks:
  - pre_tool_call  → logs the tool ARGS (the actual command for `terminal`) and
    returns None (= allow). This is where phase 2 will add the egress veto.
  - post_tool_call → logs the result size. (NOTE: post_tool_call arrives with
    params=None for the terminal tool, so the command is only visible at pre.)

This tells us what the agent actually fetches via the shell BEFORE we block.
stdlib only; all output to stdout with a `[gateway_shield]` prefix (greppable in
Render logs). post_tool_call return values are ignored by Hermes; pre_tool_call
can veto with {"action":"block","message":...} — NOT used yet (phase 1).
"""

import json
import re

_NET_TOKEN = re.compile(
    r"\b(curl|wget|nc|ncat|telnet|aria2c|http|https|requests\.(get|post)|urllib|httpx|fetch|yt-dlp|youtube-dl|xurl)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
# Best-effort redaction so audit lines never leak creds a command might carry.
_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|x-subscription-token:\s*\S+|api[_-]?key\s*[=:]\s*\S+|sk-[A-Za-z0-9_\-]{8,}|sk-or-[A-Za-z0-9_\-]{8,})"
)


def _redact(s):
    return _SECRET.sub("[REDACTED]", s)


def _command_of(params):
    if isinstance(params, dict):
        for k in ("command", "cmd", "script", "input", "code", "args"):
            v = params.get(k)
            if isinstance(v, str):
                return v
        return json.dumps(params, ensure_ascii=False)
    if params is None:
        return ""
    return str(params)


def on_pre_tool_call(tool_name, params=None, *args, **kwargs):
    try:
        cmd = _redact(_command_of(params))[:600]
        urls = _URL.findall(cmd)
        net = bool(urls) or bool(_NET_TOKEN.search(cmd))
        print(
            f"[gateway_shield][audit-pre] tool={tool_name} net={net} urls={urls[:5]} "
            f"ptype={type(params).__name__} cmd={cmd!r}",
            flush=True,
        )
    except Exception as e:  # never let auditing break a tool call
        print(f"[gateway_shield][audit-pre] hook_error={e!r}", flush=True)
    return None  # phase 1: observe only (allow). phase 2 will block here.


def on_post_tool_call(tool_name, params=None, result=None, *args, **kwargs):
    try:
        rlen = len(result) if isinstance(result, str) else -1
        print(f"[gateway_shield][audit-post] tool={tool_name} result_len={rlen}", flush=True)
    except Exception as e:
        print(f"[gateway_shield][audit-post] hook_error={e!r}", flush=True)


def register(ctx):
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    print("[gateway_shield] audit hooks registered (phase 1: observe-only, pre+post)", flush=True)
