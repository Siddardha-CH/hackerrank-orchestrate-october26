"""Case reconstruction: who is the subject, which resources are theirs, what state is each
resource in at ``audit_at``, and what the policy requires.

Linking strategy (in order of strength):

1. **Direct identifier links** – an observation whose lookup key / stored identifiers match the
   subject's current or historical email, user_id, phone or email hash.
2. **Catalog links** – ``LINK_RESOURCE_IDENTITY`` activities map business aliases (file names,
   statement numbers, customer keys) to resource ids and subjects.
3. **Workflow links** – records that have already been de-identified carry no identifier, so they
   are attributed through the deletion workflow that touched them: deletion-worker activities in the
   request's processing window, grouped into chains by their fixed scheduling cadence, scored by
   chain-mates that are directly linked, co-occurrence in the same evidence capture as the
   subject's other records, and timing relative to ``reported_at``.  A global greedy assignment
   prevents one record being attributed to two requests.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .data import Identity, World, parse_ts
from .evidence import Observation

WORKFLOW_TYPES = {
    "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
    "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS", "RETAIN_RECORD",
}
CHAIN_GAPS = (390, 449, 1110, 1169)  # seconds between consecutive actions of one workflow run
GAP_TOL = 3

# category -> required action (from deletion_rules.csv semantics)
PREFIX_CATEGORY = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "analytics": "ANALYTICS_PROFILE",
    "support": "SUPPORT_MESSAGE", "export": "USER_EXPORT", "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE", "audit_record": "SECURITY_AUDIT_LOG", "tombstone": "ACCOUNT_TOMBSTONE",
    "legal_hold": "LEGAL_HOLD_RECORD", "marketing": "MARKETING_PROFILE", "cache": "CACHE_ENTRY",
    "email_delivery": "EMAIL_DELIVERY_LOG", "object": "SUPPORT_ATTACHMENT", "telemetry": "PRODUCT_TELEMETRY",
}


def prefix_of(rid: str) -> str:
    for p in sorted(PREFIX_CATEGORY, key=len, reverse=True):
        if rid.startswith(p + "_"):
            return p
    return rid.split("_")[0]


@dataclass
class Request:
    case_id: str
    email: str
    requested_at: object
    reported_status: str
    reported_at: object
    audit_at: object
    text: str
    deletion: bool = True
    identity: Identity | None = None
    resources: dict = field(default_factory=dict)  # rid -> set(reasons)
    home_files: set = field(default_factory=set)


class Engine:
    def __init__(self, world: World, observations: list[Observation], manifest: dict):
        self.w = world
        self.manifest = manifest
        self.acts = world.activities
        for a in self.acts:
            a["_t"] = parse_ts(a["event_time"])
        self._apply_catalog_links(observations)
        self.obs = observations
        self.by_res: dict[str, list[Observation]] = defaultdict(list)
        self.key_index: dict[str, set] = defaultdict(set)
        for o in self.obs:
            self.by_res[o.resource_id].append(o)
            for k in o.keys:
                self.key_index[k].add(o.resource_id)
        self.act_by_res: dict[str, list] = defaultdict(list)
        for a in self.acts:
            self.act_by_res[a["resource_id"]].append(a)
        self._build_chains()

    # ------------------------------------------------------------------ catalog links
    LINK_RE = re.compile(r"(?:linked|confirmed) (\S+) \(([^)]*)\)")

    def _apply_catalog_links(self, observations):
        self.catalog = {}
        alias_to_rid = {}
        for a in self.acts:
            if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            m = self.LINK_RE.search(a["details"])
            if not m:
                continue
            rid, alias = m.group(1), m.group(2)
            emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", a["details"])
            users = re.findall(r"\buser_\d+\b", a["details"].split(" to ", 1)[-1] if " to " in a["details"] else a["details"])
            self.catalog[rid] = dict(alias=alias, emails=[e.lower().rstrip(".") for e in emails], users=users,
                                     activity=a, system=a["target_system"])
            alias_to_rid[alias.lower()] = rid
        for o in observations:
            if o.resource_id.startswith("alias:"):
                alias = o.resource_id[6:].lower()
                rid = alias_to_rid.get(alias)
                if rid:
                    o.resource_id = rid
                    o.system = self.catalog[rid]["system"]
            info = self.catalog.get(o.resource_id)
            if info:
                o.system = info["system"]
                o.keys |= set(info["emails"]) | set(info["users"])

    # ------------------------------------------------------------------ chains / workflow runs
    @staticmethod
    def is_workflow(a) -> bool:
        if a["source_system"] == "deletion_worker" and a["event_type"] in WORKFLOW_TYPES:
            return True
        # replication / connector / restore jobs that re-create data are part of the same run
        return a["event_type"] in ("SYNC_RECORD", "RESTORE_BACKUP") and (
            a["details"].startswith("Replication worker") or "repopulated" in a["details"])

    def _build_chains(self):
        """Group workflow activities into runs.

        Follow-up actions of one deletion run are scheduled at a fixed cadence (6.5/7.5 min before the
        report or 18.5/19.5 min after it); the account deletion that opened the run precedes the first
        follow-up by a whole number of minutes plus a constant 41 s (pre-report runs) or 52 s
        (post-report runs).  These regularities let records that no longer carry identifiers be
        attributed to the same run as records that still do."""
        wf = [a for a in self.acts if self.is_workflow(a)]
        accts = [a for a in wf if a["resource_id"].startswith("account_") and a["event_type"] == "DELETE_RECORD"]
        rest = [a for a in wf if a not in accts and not a["resource_id"].startswith("account_")]
        rest.sort(key=lambda a: a["_t"])
        parent = {a["activity_id"]: a["activity_id"] for a in rest}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i, a in enumerate(rest):
            for b in rest[i + 1:]:
                gap = (b["_t"] - a["_t"]).total_seconds()
                if gap > max(CHAIN_GAPS) + GAP_TOL:
                    break
                if any(abs(gap - g) <= GAP_TOL for g in CHAIN_GAPS):
                    parent[find(b["activity_id"])] = find(a["activity_id"])
        groups = defaultdict(list)
        for a in rest:
            groups[find(a["activity_id"])].append(a)
        runs = [dict(acts=sorted(m, key=lambda a: a["_t"]), account=None) for m in groups.values()]
        # pair account deletions with the run they opened
        pairs = []
        for ac in accts:
            for ri, run in enumerate(runs):
                g = (run["acts"][0]["_t"] - ac["_t"]).total_seconds()
                sec = g % 60
                if 10 * 60 <= g <= 55 * 60 and 39 <= sec <= 43:
                    pairs.append((abs(sec - 41), g, ac["activity_id"], ri))
                elif 75 * 60 <= g <= 140 * 60 and 50 <= sec <= 54:
                    pairs.append((abs(sec - 52), g, ac["activity_id"], ri))
        pairs.sort()
        used_a, used_r = set(), set()
        acct_by_id = {a["activity_id"]: a for a in accts}
        for _, _, aid, ri in pairs:
            if aid in used_a or ri in used_r:
                continue
            used_a.add(aid)
            used_r.add(ri)
            runs[ri]["account"] = acct_by_id[aid]
        for ac in accts:
            if ac["activity_id"] not in used_a:
                runs.append(dict(acts=[], account=ac))
        self.runs = runs
        self.chain_of = {}
        for run in runs:
            rids = [m["resource_id"] for m in run["acts"]] + ([run["account"]["resource_id"]] if run["account"] else [])
            for m in run["acts"] + ([run["account"]] if run["account"] else []):
                self.chain_of[m["activity_id"]] = rids

    # ------------------------------------------------------------------ linking
    def direct_links(self, req: Request, same_user: list[Request]) -> set:
        keys = req.identity.strong_keys()
        rids = set()
        for k in keys:
            rids |= self.key_index.get(k, set())
        out = set()
        for rid in rids:
            if rid.startswith(("alias:", "order:", "__scope__")):
                continue
            # only evidence that existed by the audit cut-off can make a record part of this request
            mine = [o for o in self.by_res[rid] if o.keys & keys and parse_ts(o.ts) <= req.audit_at]
            if any(self._owner_request(o, same_user) is req for o in mine):
                out.add(rid)
        return out

    @staticmethod
    def _owner_request(o: Observation, same_user: list[Request]) -> Request:
        """With several requests from one subject, evidence belongs to the earliest request whose
        audit cut-off it precedes (later evidence belongs to the latest request)."""
        t = parse_ts(o.ts)
        for r in same_user:
            if t <= r.audit_at:
                return r
        return same_user[-1]

    def link_all(self, requests: list[Request]):
        by_user = defaultdict(list)
        for r in requests:
            uid = min(r.identity.user_ids) if r.identity.user_ids else r.email.lower()
            by_user[uid].append(r)
        for lst in by_user.values():
            lst.sort(key=lambda r: r.audit_at)
        owner_of = {}  # rid -> request (direct)
        for lst in by_user.values():
            for r in lst:
                if not r.deletion:
                    continue
                for rid in self.direct_links(r, lst):
                    r.resources.setdefault(rid, set()).add("direct")
                    owner_of.setdefault(rid, r)
        for r in requests:
            if r.deletion:
                r.home_files = {o.file_id for rid in r.resources for o in self.by_res[rid]
                                if o.keys & r.identity.strong_keys()}

        # workflow runs -> requests
        dels = [r for r in requests if r.deletion]
        status_map = {"SUCCESS": "COMPLETE", "PARTIAL": "PARTIALLY_COMPLETE", "FAILED": "NOT_STARTED"}
        cand = []
        for ri, run in enumerate(self.runs):
            members = run["acts"] + ([run["account"]] if run["account"] else [])
            rids = {m["resource_id"] for m in members}
            owners = {id(owner_of[x]) for x in rids if x in owner_of}
            t0 = min(m["_t"] for m in members)
            t1 = max(m["_t"] for m in members)
            for r in dels:
                if not (r.requested_at <= t0 and t1 <= r.reported_at + timedelta(hours=3)):
                    continue
                if owners and id(r) not in owners:
                    continue
                score = 100.0 * sum(1 for x in rids if x in owner_of and owner_of[x] is r)
                ok_time = False
                if run["account"]:
                    d = (run["account"]["_t"] - r.reported_at).total_seconds() / 60
                    ok_time = -80 <= d <= -40 or -15 <= d <= 15
                    exp = status_map.get(run["account"]["reported_result"])
                    score += 20 if exp == r.reported_status else -20
                if run["acts"]:
                    d = (run["acts"][0]["_t"] - r.reported_at).total_seconds() / 60
                    ok_time = ok_time or -35 <= d <= -3 or 30 <= d <= 125 or -15 <= d <= 15
                if not ok_time and score < 100:
                    continue
                score += 5 if ok_time else 0
                score += 10 * sum(1 for x in rids if any(o.file_id in r.home_files for o in self.by_res.get(x, [])))
                score -= abs((t0 - r.reported_at).total_seconds()) / 1e6
                cand.append((score, ri, r))
        cand.sort(key=lambda c: (-c[0], c[1], c[2].case_id))
        taken_runs, has_account, has_loose = set(), set(), set()
        for score, ri, r in cand:
            run = self.runs[ri]
            if ri in taken_runs:
                continue
            if run["account"] and id(r) in has_account:
                continue
            if not run["account"] and score < 100 and id(r) in has_loose:
                continue
            taken_runs.add(ri)
            if run["account"]:
                has_account.add(id(r))
            elif score < 100:
                has_loose.add(id(r))
            for m in run["acts"] + ([run["account"]] if run["account"] else []):
                x = m["resource_id"]
                if x in owner_of and owner_of[x] is not r:
                    continue  # directly attributed to another request
                r.resources.setdefault(x, set()).add("workflow")
