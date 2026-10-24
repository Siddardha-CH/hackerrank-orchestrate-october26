"""End-to-end audit pipeline: requests -> linked resources -> assessments -> steps."""
from __future__ import annotations

import csv
import json

from . import evidence
from .data import World, parse_ts
from .engine import Engine, Request
from .intent import classify
from .policy import assess, load_rules, plan


def _requests(rows, world: World) -> list[Request]:
    out = []
    for r in rows:
        req = Request(r["case_id"], r["email"], parse_ts(r["requested_at"]), r["reported_status"],
                      parse_ts(r["reported_at"]), parse_ts(r["audit_at"]), r["request_text"])
        req.deletion, req.intent_source = classify(req.text)
        req.identity = world.resolve(req.email)
        out.append(req)
    return out


class Auditor:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.world = World(dataset_dir)
        obs, manifest = evidence.load_all(dataset_dir)
        self.engine = Engine(self.world, obs, manifest)
        self.rules = load_rules(self.world.rules)
        # capture coverage: system -> [(ts, captured_at, file_id)] for absence-by-omission
        self.coverage: dict[str, list] = {}
        for o in obs:
            if o.resource_id.startswith("__scope__:"):
                self.coverage.setdefault(o.system, []).append((o.ts, o.captured_at, o.file_id))

    def omission(self, rid, system, after, audit_at, listed_files):
        """Latest admissible capture taken after `after` that covers `system` but does not list `rid`."""
        best = None
        for ts, cap, fid in self.coverage.get(system, []):
            if fid in listed_files or parse_ts(cap) > audit_at:
                continue
            if after is not None and ts <= after:
                continue
            key = (ts, cap, fid)
            if best is None or key > best:
                best = key
        return (best[0], best[2]) if best else None

    def run(self, rows: list[dict], context_rows: list[dict] | None = None) -> list[dict]:
        """Audit `rows`.  `context_rows` are other participant-facing requests that share the same
        activity stream; they take part in workflow attribution but produce no output."""
        reqs = _requests(rows, self.world)
        ctx = _requests(context_rows or [], self.world)
        ids = {r.case_id for r in reqs}
        self.engine.link_all(reqs + [c for c in ctx if c.case_id not in ids])
        out = []
        for req in sorted(reqs, key=lambda r: _case_key(r.case_id)):
            if not req.deletion:
                out.append({"case_id": req.case_id, "deletion_status": "NOT_APPLICABLE", "steps": [], "req": req,
                            "assessments": []})
                continue
            assessments = []
            for rid in sorted(req.resources):
                acts = self.engine.act_by_res.get(rid, [])
                dels = [x["event_time"] for x in acts if x["event_type"] == "DELETE_RECORD"
                        and parse_ts(x["event_time"]) <= req.audit_at]
                since = max(dels) if dels else req.requested_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                assessments.append(assess(rid, self.engine.by_res.get(rid, []), acts, req.audit_at, self.rules,
                                          self.omission, since))
            status, steps = plan(assessments)
            out.append({"case_id": req.case_id, "deletion_status": status, "steps": steps, "req": req,
                        "assessments": assessments})
        self.review = self._review_queue(out)
        return out

    def _review_queue(self, results) -> list[dict]:
        """Cases a human should look at, with the reason.  The answer in output.csv is unchanged."""
        ids = {r["case_id"] for r in results}
        queue = [dict(x) for x in self.engine.review if x["case_id"] in ids]
        for r in results:
            req = r["req"]
            if req.intent_source not in ("rule:targeted_erasure", "rule:multilingual_erasure", "rule:non_deletion"):
                queue.append(dict(case_id=r["case_id"], reason="intent_not_decided_by_rules",
                                  detail=f"intent source {req.intent_source}"))
            if r["deletion_status"] == "NOT_APPLICABLE":
                continue
            for a in r["assessments"]:
                if not a.known and a.action != "RETAIN" and not any(x.violation for x in r["assessments"]):
                    queue.append(dict(case_id=r["case_id"], reason="state_unproven",
                                      detail=f"{a.rid}: no admissible evidence of its state"))
                if r["deletion_status"] == "COMPLETE" and a.proof == "omission":
                    queue.append(dict(case_id=r["case_id"], reason="absence_by_omission_only",
                                      detail=f"{a.rid}: absent only because {a.evidence} does not list it"))
                why = req.resources.get(a.rid, set())
                if why == {"workflow_timing"} and not any(o.file_id in req.home_files
                                                   for o in self.engine.by_res.get(a.rid, [])):
                    queue.append(dict(case_id=r["case_id"], reason="timing_only_link",
                                      detail=f"{a.rid}: attributed by workflow timing only, no shared capture"))
        queue.sort(key=lambda x: (_case_key(x["case_id"]), x["reason"], x["detail"]))
        return queue


def _case_key(cid: str):
    try:
        return int(cid.split("_")[-1])
    except ValueError:
        return cid


def write_review_queue(queue: list[dict], path: str):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "reason", "detail", "llm_note"])
        w.writeheader()
        for row in queue:
            w.writerow({k: row.get(k, "") for k in w.fieldnames})


def write_output(results: list[dict], path: str):
    rows = sorted(results, key=lambda r: _case_key(r["case_id"]))  # natural order: case_33 < case_100
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in rows:
            w.writerow([r["case_id"], r["deletion_status"],
                        json.dumps(r["steps"], ensure_ascii=False, separators=(",", ":"))])
