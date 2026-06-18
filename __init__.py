"""gateway_shield — KIN-282 egress audit (phase 1).

Registers a post_tool_call hook (observation-only; its return value is ignored by
Hermes) that logs every tool call and, for the `terminal` tool, the command plus
whether it looks like raw network egress. This tells us what the agent actually
fetches via the shell BEFORE we add a pre_tool_call veto in phase 2.

stdlib only. All output goes to stdout with a `[gateway_shield]` prefix so it is
greppable in Render logs.
"""

import json
import re

# Heuristics for "the agent is fetching the network from the shell".
_NET_TOKEN = re.compile(
    r"\b(curl|wget|nc|ncat|telnet|aria2c|http|https|requests\.(get|post)|urllib|httpx|fetch|yt-dlp|youtube-dl|xurl)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
# Best-effort redaction so audit lines never leak creds the command might carry.
_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|x-subscription-token:\s*\S+|api[_-]?key\s*[=:]\s*\S+|sk-[A-Za-z0-9_\-]{8,}|sk-or-[A-Za-z0-9_\-]{8,})"
)


def _redact(s):
    return _SECRET.sub("[REDACTED]", s)


def _command_of(params):
    if isinstance(params, dict):
        for k in ("command", "cmd", "script", "input"):
            if isinstance(params.get(k), str):
                return params[k]
        return json.dumps(params, ensure_ascii=False)
    return str(params)


def on_tool_call(tool_name, params=None, result=None, *args, **kwargs):
    try:
        if tool_name == "terminal":
            cmd = _redact(_command_of(params))[:600]
            urls = _URL.findall(cmd)
            net = bool(urls) or bool(_NET_TOKEN.search(cmd))
            print(
                f"[gateway_shield][audit] tool=terminal net={net} urls={urls[:5]} cmd={cmd!r}",
                flush=True,
            )
        else:
            rlen = len(result) if isinstance(result, str) else -1
            print(
                f"[gateway_shield][audit] tool={tool_name} result_len={rlen}",
                flush=True,
            )
    except Exception as e:  # never let auditing break a tool call
        print(f"[gateway_shield][audit] hook_error={e!r}", flush=True)


def register(ctx):
    ctx.register_hook("post_tool_call", on_tool_call)
    print("[gateway_shield] audit hook registered (phase 1: observe-only)", flush=True)
