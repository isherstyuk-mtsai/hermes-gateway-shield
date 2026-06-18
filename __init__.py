"""gateway_shield — KIN-282 egress audit (phase 1, OBSERVE ONLY).

DIAGNOSTIC build: Hermes does not pass tool args as the 2nd positional param
(empirically params=None), so we dump the FULL hook call shape (args + kwargs,
redacted) to discover where the `terminal` command actually lives. Once known,
the next build will extract it cleanly and (phase 2) veto raw egress here.

stdlib only; output to stdout with `[gateway_shield]` prefix (Render logs).
pre_tool_call may veto with {"action":"block","message":...} — NOT used yet.
"""

import re

_NET_TOKEN = re.compile(
    r"\b(curl|wget|nc|ncat|telnet|aria2c|http|https|requests\.(get|post)|urllib|httpx|fetch|yt-dlp|youtube-dl|xurl)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|x-subscription-token:\s*\S+|api[_-]?key\s*[=:]\s*\S+|sk-[A-Za-z0-9_\-]{8,}|sk-or-[A-Za-z0-9_\-]{8,})"
)


def _redact(s):
    return _SECRET.sub("[REDACTED]", s)


def _dump(stage, tool_name, args, kwargs):
    try:
        shape = _redact(repr({"args": args, "kwargs": kwargs}))[:800]
        net = bool(_URL.search(shape)) or bool(_NET_TOKEN.search(shape))
        print(f"[gateway_shield][{stage}] tool={tool_name} net={net} shape={shape}", flush=True)
    except Exception as e:
        print(f"[gateway_shield][{stage}] hook_error={e!r}", flush=True)


def on_pre_tool_call(tool_name, *args, **kwargs):
    _dump("audit-pre", tool_name, args, kwargs)
    return None  # phase 1: observe only (allow). phase 2 will block here.


def on_post_tool_call(tool_name, *args, **kwargs):
    _dump("audit-post", tool_name, args, kwargs)


def register(ctx):
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    print("[gateway_shield] audit hooks registered (phase 1: diagnostic dump)", flush=True)
