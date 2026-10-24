"""End-to-end audit pipeline: requests -> linked resources -> assessments -> steps."""
from __future__ import annotations

import csv
import json

from . import evidence
from .data import World, parse_ts
from .engine import Engine, Request
from .intent import authorises_deletion
from .policy import assess, load_rules, plan


def _requests(rows, world: World) -> list[Request]:
    out = []
    for r in rows:
        req = Request(r["case_id"], r["email"], parse_ts(r["requested_at"]), r["reported_status"],
                      parse_ts(r["reported_at"]), parse_ts(r["audit_at"]), r["request_text"])
        req.deletion = authorises_deletion(req.text)
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
        return out


def _case_key(cid: str):
    try:
        return int(cid.split("_")[-1])
    except ValueError:
        return cid


def write_output(results: list[dict], path: str):
    rows = sorted(results, key=lambda r: _case_key(r["case_id"]))  # natural order: case_33 < case_100
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in rows:
            w.writerow([r["case_id"], r["deletion_status"],
                        json.dumps(r["steps"], ensure_ascii=False, separators=(",", ":"))])
