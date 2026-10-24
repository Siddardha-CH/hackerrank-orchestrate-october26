"""Does the request text authorise deletion?

A transparent multilingual rule classifier handles the request texts.  It first looks
for explicit statements that the person does *not* want deletion or wants a narrower
action (access, correction, export/portability, marketing opt-out, login help,
invoices, "don't delete anything").  Otherwise an erasure verb/noun in any of the
supported languages authorises deletion.

If neither signal is present and ``ANTHROPIC_API_KEY`` is set, ``llm_classify`` asks
Claude with ``INTENT_PROMPT``; without a model the conservative answer is "not a
deletion request" (no destructive action without authorisation).
"""
from __future__ import annotations

import json
import os
import re

DELETE_PATTERNS = [
    r"\bdelet(e|ed|ing|ion)\b", r"\berase(d)?\b", r"\berasure\b", r"\bremov(e|ed|al)\b",
    r"\bclose (my|this|the) account\b", r"\bclosed my account\b", r"\bis gone\b", r"\bdisconnected my account\b",
    # Spanish / Portuguese / French / Japanese / Korean / German / Italian
    r"eliminaci[oó]n", r"\beliminar\b", r"\bborrar\b", r"exclus[aã]o", r"\bexcluir\b", r"\bapagar\b",
    r"suppression", r"\bsupprimer\b", r"削除", r"消去", r"삭제", r"l[öo]schung", r"\bl[öo]schen\b",
    r"cancellazione", r"\bcancellare\b",
]

# Explicit statements that the person does NOT want deletion, or wants a narrower action.
NON_DELETION_PATTERNS = [
    r"\bnot (asking|a request) (for|to) (deletion|delete|erase)", r"\b(don't|do not) (delete|close|remove|erase)",
    r"\bkeep the account\b", r"\bleave (the account|my profile)\b", r"\bwithout removing\b",
    r"\bcontinue using\b", r"\bmarketing lists? only\b", r"\bstill (need|want|use)\b",
    r"\bstop the promotional\b", r"\bunsubscribe\b", r"\bportable format\b", r"\bmisspelled\b",
    r"\bout of date\b", r"\bchange the email address\b", r"\breset(ting)? the login\b",
    r"\bwhat personal information you hold\b", r"\bcopy of (last year's invoices|the information)\b",
]

INTENT_PROMPT = """Classify a customer's privacy request. Answer JSON {"deletion": true|false}.
deletion=true only when the customer asks to delete/erase/close their account or personal data.
Access, copies, export/portability, corrections, marketing opt-out, login help or invoice requests
are deletion=false. The text may be in any language.
Request: """

USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0}


def llm_classify(text: str) -> bool | None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    client = anthropic.Anthropic()
    msg = client.messages.create(model=os.environ.get("AUDIT_TEXT_MODEL", "claude-haiku-5-5"), max_tokens=20,
                                 messages=[{"role": "user", "content": INTENT_PROMPT + text}])
    USAGE["calls"] += 1
    USAGE["input_tokens"] += msg.usage.input_tokens
    USAGE["output_tokens"] += msg.usage.output_tokens
    out = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    try:
        return bool(json.loads(out[out.find("{"):out.rfind("}") + 1])["deletion"])
    except Exception:
        return None


def authorises_deletion(text: str) -> bool:
    t = text.lower().replace("’", "'")
    if any(re.search(p, t) for p in NON_DELETION_PATTERNS):
        return False
    if any(re.search(p, t) for p in DELETE_PATTERNS):
        return True
    return bool(llm_classify(text))
