"""Screenshot understanding.

Application screenshots are turned into structured records with a vision-language
model.  Extraction is cached in ``code/audit/vision_cache.json`` keyed by file name
and SHA-256 of the image bytes so that a full run is deterministic and costs zero
tokens once the cache is warm.

* If a cache entry exists for the exact image bytes it is used.
* Otherwise, when ``ANTHROPIC_API_KEY`` is set, the image is sent to Claude with
  ``VISION_PROMPT`` and the JSON answer is cached.
* Otherwise the image contributes no observations (a warning is recorded).

The cache shipped with the repository was produced with Claude (claude-opus-5-5)
reading each screenshot using exactly ``VISION_PROMPT``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

CACHE_PATH = os.path.join(os.path.dirname(__file__), "vision_cache.json")
MODEL = os.environ.get("AUDIT_VISION_MODEL", "claude-opus-5-5")

VISION_PROMPT = """You are reading a screenshot of an internal Northstar Shop business application.
Extract only facts that are visible. Return JSON:
{"application": str, "subject": {"name": str|null, "emails": [str], "user_ids": [str]},
 "records": [{"resource_id": str|null, "alias": str|null, "system": str,
              "category": one of USER_PROFILE|SEARCH_INDEX_ENTRY|ANALYTICS_PROFILE|SUPPORT_MESSAGE|
                         SUPPORT_ATTACHMENT|USER_EXPORT|MARKETING_PROFILE|SECURITY_AUDIT_LOG|
                         BACKUP_ARCHIVE|DATA_FLOW|ACCOUNT_TOMBSTONE|null,
              "present": bool, "exposed": bool|null, "enabled": bool|null,
              "restore_allowed": bool|null, "identifiers": [str]}]}
Rules: one record per row/panel that refers to a customer data resource. `resource_id` is an
internal id such as account_123 / search_45 / data_flow_9; when the row is identified only by a file
name, statement number or customer key put it in `alias`. `identifiers` lists every email, user_id,
phone or name shown for that row. `exposed` is true when direct identifiers (name/email/phone) are
displayed for the customer. `enabled` is true for connectors shown as running/healthy/continuous.
Ignore rows that clearly belong to staff or business accounts."""

_cache = None


def _load():
    global _cache
    if _cache is None:
        _cache = json.load(open(CACHE_PATH, encoding="utf-8")) if os.path.exists(CACHE_PATH) else {}
    return _cache


USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_hits": 0, "model": MODEL}


def _call_model(path: str) -> dict | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    client = anthropic.Anthropic()
    data = base64.standard_b64encode(open(path, "rb").read()).decode()
    msg = client.messages.create(
        model=MODEL, max_tokens=2000,
        messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}},
            {"type": "text", "text": VISION_PROMPT}]}])
    USAGE["calls"] += 1
    USAGE["input_tokens"] += msg.usage.input_tokens
    USAGE["output_tokens"] += msg.usage.output_tokens
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def extract(path: str, root: str) -> dict:
    cache = _load()
    name = os.path.basename(path)
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    hit = cache.get(name)
    if hit and hit.get("sha256") == digest:
        USAGE["cache_hits"] += 1
        return hit
    res = _call_model(path)
    if res is None:
        print(f"[vision] no cached extraction for {name} and no model available", file=sys.stderr)
        return {"records": []}
    res["sha256"] = digest
    cache[name] = res
    json.dump(cache, open(CACHE_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    return res
