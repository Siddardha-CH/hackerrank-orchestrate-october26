"""Optional LLM second opinion for the review queue.

Only cases the deterministic engine flagged are sent (``code/prompts/case_review.md``).  The model's
note is attached to the queue row; it never changes ``output.csv`` - a human decides.
"""
from __future__ import annotations

import json
import os

from .intent import load_prompt

USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "model": os.environ.get("AUDIT_REVIEW_MODEL", "claude-opus-5-5")}


def case_packet(result, engine, manifest) -> dict:
    req = result["req"]
    obs = []
    for rid in sorted(req.resources):
        for o in engine.by_res.get(rid, []):
            obs.append(dict(file=o.file_id, captured=manifest.get(o.file_id, {}).get("captured_at"), ts=o.ts,
                            system=o.system, resource=rid, present=o.present, exposed=o.exposed,
                            enabled=o.enabled, restore_allowed=o.restore_allowed, linked_by=sorted(req.resources[rid])))
    acts = [dict(id=a["activity_id"], t=a["event_time"], type=a["event_type"], resource=a["resource_id"],
                 result=a["reported_result"]) for rid in sorted(req.resources) for a in engine.act_by_res.get(rid, [])]
    return dict(case_id=req.case_id, email=req.email, audit_at=str(req.audit_at), reported_status=req.reported_status,
                identifiers=sorted(req.identity.strong_keys()), observations=obs, activities=acts,
                verdict=result["deletion_status"], steps=result["steps"])


def llm_review(queue, results, engine, manifest, limit=50):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return queue
    try:
        import anthropic  # type: ignore
    except ImportError:
        return queue
    client = anthropic.Anthropic()
    prompt = load_prompt("case_review.md").split("---", 1)[-1].strip()
    by_case = {r["case_id"]: r for r in results}
    for row in queue[:limit]:
        packet = case_packet(by_case[row["case_id"]], engine, manifest)
        packet["flag"] = {"reason": row["reason"], "detail": row["detail"]}
        msg = client.messages.create(model=USAGE["model"], max_tokens=300, messages=[
            {"role": "user", "content": prompt + "\n\nCASE:\n" + json.dumps(packet, default=str)}])
        USAGE["calls"] += 1
        USAGE["input_tokens"] += msg.usage.input_tokens
        USAGE["output_tokens"] += msg.usage.output_tokens
        row["llm_note"] = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    return queue
