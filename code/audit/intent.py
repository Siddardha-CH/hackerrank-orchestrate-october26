"""Does the request text authorise deletion?

Decision order (most specific first):

1. **Explicit non-deletion** - statements that the person does *not* want deletion or wants a
   narrower action (access, correction, export/portability, marketing opt-out, login help,
   invoices, "don't delete anything").  -> not a deletion request.
2. **Targeted erasure** - an erasure verb whose object is the account or the person's data
   ("remove my account", "erase the account linked to...", "would like it permanently deleted"
   in a sentence about the account, "account deletion", "personal-data deletion"), or the
   equivalent nouns in Spanish / Portuguese / French / Japanese / Korean / German / Italian.
   A verb aimed at a single field ("remove the old shipping address from my profile") does
   *not* qualify.  -> deletion request.
3. **Undecided** - neither signal.  If ``ANTHROPIC_API_KEY`` is set the text is classified by
   Claude with ``code/prompts/intent_classification.md``; otherwise the conservative answer is
   "not a deletion request": no destructive action without clear authorisation.

``classify`` returns (decision, source) so undecided cases can be routed to a reviewer.
"""
from __future__ import annotations

import json
import os
import re

PROMPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")

VERB = r"(?:delet\w*|eras\w*|remov\w*|clos\w*|wip\w*|purg\w*|disconnect\w*|deactivat\w*)"
PARTICIPLE = r"(?:deleted|erased|removed|closed|wiped|purged|deactivated)"
TARGET = (r"(?:account|profile|personal (?:data|details|information|info)|my data|all (?:of )?my data|data|"
          r"records|everything|search results?|cop(?:y|ies)|traces?|exports?|archive|identity document|"
          r"contact details|details)")

TARGETED_PATTERNS = [
    rf"\b{VERB}\b(?:\W+\w+){{0,4}}?\W+{TARGET}\b",            # erase-verb -> object within 4 words
    rf"\b(?:account|profile)\b[^.?!]*\b{PARTICIPLE}\b",       # "...the account ... to be erased"
    rf"\b(?:it|this|that)\b(?:\W+\w+){{0,2}}?\W+{PARTICIPLE}\b",  # "would like it permanently deleted"
    rf"\b{VERB}\W+(?:it|this|that)\b",                           # "before deleting it"
    r"\b(?:account|personal[- ]data|data)[- ](?:deletion|erasure|closure)\b",
    r"\bdeletion of (?:the|my|this) account\b",
    r"\b(?:account|profile)(?: page)? (?:is|was) gone\b",
]
# "it/this/that + participle" only counts in a text that is about the account
CONTEXT_FOR_PRONOUN = r"\baccount\b"

MULTILINGUAL_PATTERNS = [
    r"eliminaci[oó]n", r"\beliminar\b", r"\bborrar\b", r"exclus[aã]o", r"\bexcluir\b", r"\bapagar\b",
    r"suppression", r"\bsupprimer\b", r"削除", r"消去", r"삭제", r"l[öo]schung", r"\bl[öo]schen\b",
    r"cancellazione", r"\bcancellare\b",
]

NON_DELETION_PATTERNS = [
    r"\bnot (?:asking|a request) (?:for|to) (?:deletion|delete|erase)", r"\b(?:don't|do not) (?:delete|close|remove|erase)",
    r"\bkeep the account\b", r"\bleave (?:the account|my profile)\b", r"\bwithout removing\b",
    r"\bcontinue using\b", r"\bmarketing lists? only\b", r"\bstill (?:need|want|use)\b",
    r"\bstop the promotional\b", r"\bunsubscribe\b", r"\bportable format\b", r"\bmisspelled\b",
    r"\bout of date\b", r"\bchange the email address\b", r"\breset(?:ting)? the login\b",
    r"\bwhat personal information you hold\b", r"\bcopy of (?:last year's invoices|the information)\b",
]

USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0}


def load_prompt(name: str) -> str:
    with open(os.path.join(PROMPT_DIR, name), encoding="utf-8") as fh:
        return fh.read()


def llm_classify(text: str) -> bool | None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    client = anthropic.Anthropic()
    msg = client.messages.create(model=os.environ.get("AUDIT_TEXT_MODEL", "claude-haiku-5-5"), max_tokens=20,
                                 messages=[{"role": "user",
                                            "content": load_prompt("intent_classification.md") + "\n\nRequest: " + text}])
    USAGE["calls"] += 1
    USAGE["input_tokens"] += msg.usage.input_tokens
    USAGE["output_tokens"] += msg.usage.output_tokens
    out = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    try:
        return bool(json.loads(out[out.find("{"):out.rfind("}") + 1])["deletion"])
    except (ValueError, KeyError):
        return None


def classify(text: str) -> tuple[bool, str]:
    t = text.lower().replace("’", "'")
    if any(re.search(p, t) for p in NON_DELETION_PATTERNS):
        return False, "rule:non_deletion"
    for p in TARGETED_PATTERNS:
        if re.search(p, t) and ("(?:it|this|that)" not in p or re.search(CONTEXT_FOR_PRONOUN, t)):
            return True, "rule:targeted_erasure"
    if any(re.search(p, t) for p in MULTILINGUAL_PATTERNS):
        return True, "rule:multilingual_erasure"
    llm = llm_classify(text)
    if llm is not None:
        return llm, "llm"
    return False, "undecided_default_no"


def authorises_deletion(text: str) -> bool:
    return classify(text)[0]
