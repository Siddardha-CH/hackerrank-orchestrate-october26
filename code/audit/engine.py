"""Case reconstruction: who is the subject, which resources are theirs, what state is each
resource in at ``audit_at``, and what the policy requires.

Linking strategy (in order of strength):

1. **Direct identifier links** – an observation whose lookup key / stored identifiers match the
   subject's current or historical email, user_id, phone or email hash.
2. **Catalog links** – ``LINK_RESOURCE_IDENTITY`` activities map business aliases (file names,
   statement numbers, customer keys) to resource ids and subjects.
3. **Workflow links** – records that have already been de-identified carry no identifier, so they
   are attributed through the deletion workflow that touched them: deletion-worker activities in the
   request's processing window, grouped into runs by the scheduler cadence, scored by run members
   that are directly linked, co-occurrence in the same evidence capture as the subject's other
   records, and timing relative to ``reported_at``.  The cadence parameters are *learned* from
   identifier-anchored runs on every execution (calibration.py) and runs are given to requests by an
   exact maximum-weight assignment (assignment.py), so one record can never be attributed to two
   requests.  Genuine near-ties are flagged for human review.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .assignment import max_weight_assignment
from .calibration import Calibration, calibrate
from .data import Identity, World, parse_ts
from .evidence import Observation

WORKFLOW_TYPES = {
    "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
    "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS", "RETAIN_RECORD",
}
AMBIGUITY_MARGIN = 1.0  # score difference below which two candidate requests count as a genuine tie
DIRECT = 100.0          # weight of one directly attributed run member

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


def case_num(cid: str) -> int:
    try:
        return int(cid.split("_")[-1])
    except ValueError:
        return 0


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
    intent_source: str = ""
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
        self.cal = Calibration()
        self.runs: list = []
        self.chain_of: dict = {}
        self.review: list = []  # ambiguous attributions for a human reviewer

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

    # ------------------------------------------------------------------ workflow runs
    @staticmethod
    def is_workflow(a) -> bool:
        if a["source_system"] == "deletion_worker" and a["event_type"] in WORKFLOW_TYPES:
            return True
        # replication / connector / restore jobs that re-create data are part of the same run
        return a["event_type"] in ("SYNC_RECORD", "RESTORE_BACKUP") and (
            a["details"].startswith("Replication worker") or "repopulated" in a["details"])

    def _build_chains(self):
        """Group workflow activities into runs using the calibrated cadence: follow-up actions are
        linked when their gap matches a learned interval; an account deletion is paired with the run
        it opened when the gap lies in a learned range and carries the learned seconds residue."""
        cal = self.cal
        wf = [a for a in self.acts if self.is_workflow(a)]
        accts = [a for a in wf if a["resource_id"].startswith("account_") and a["event_type"] == "DELETE_RECORD"]
        acct_ids = {a["activity_id"] for a in accts}
        rest = sorted((a for a in wf if a["activity_id"] not in acct_ids and not a["resource_id"].startswith("account_")),
                      key=lambda a: (a["_t"], a["activity_id"]))
        parent = {a["activity_id"]: a["activity_id"] for a in rest}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        max_gap = max(cal.chain_gaps, default=0) + cal.gap_tolerance
        for i, a in enumerate(rest):
            for b in rest[i + 1:]:
                gap = (b["_t"] - a["_t"]).total_seconds()
                if gap > max_gap:
                    break
                if any(abs(gap - g) <= cal.gap_tolerance for g in cal.chain_gaps):
                    parent[find(b["activity_id"])] = find(a["activity_id"])
        groups = defaultdict(list)
        for a in rest:
            groups[find(a["activity_id"])].append(a)
        runs = [dict(acts=sorted(m, key=lambda a: (a["_t"], a["activity_id"])), account=None) for m in groups.values()]
        runs.sort(key=lambda r: (r["acts"][0]["_t"], r["acts"][0]["activity_id"]))
        pairs = []
        for ac in accts:
            for ri, run in enumerate(runs):
                g = (run["acts"][0]["_t"] - ac["_t"]).total_seconds()
                for spec in cal.opener.values():
                    d = abs(g % 60 - spec["residue"])
                    d = min(d, 60 - d)
                    if spec["lo"] <= g <= spec["hi"] and d <= cal.residue_tolerance:
                        pairs.append((d, g, ac["activity_id"], ri))
        pairs.sort()
        used_a, used_r = set(), set()
        acct_by_id = {a["activity_id"]: a for a in accts}
        for _, _, aid, ri in pairs:
            if aid in used_a or ri in used_r:
                continue
            used_a.add(aid)
            used_r.add(ri)
            runs[ri]["account"] = acct_by_id[aid]
        for ac in sorted(accts, key=lambda a: (a["_t"], a["activity_id"])):
            if ac["activity_id"] not in used_a:
                runs.append(dict(acts=[], account=ac))
        self.runs = runs
        self.chain_of = {}
        for ri in range(len(runs)):
            members = self._members(ri)
            for m in members:
                self.chain_of[m["activity_id"]] = [x["resource_id"] for x in members]

    def _members(self, ri):
        run = self.runs[ri]
        return run["acts"] + ([run["account"]] if run["account"] else [])

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
        requests = sorted(requests, key=lambda r: case_num(r.case_id))  # input-order independent
        by_user = defaultdict(list)
        for r in requests:
            uid = min(r.identity.user_ids) if r.identity.user_ids else r.email.lower()
            by_user[uid].append(r)
        for lst in by_user.values():
            lst.sort(key=lambda r: (r.audit_at, case_num(r.case_id)))
        owner_of = {}  # rid -> request (direct)
        for uid in sorted(by_user):
            for r in by_user[uid]:
                if not r.deletion:
                    continue
                for rid in sorted(self.direct_links(r, by_user[uid])):
                    r.resources.setdefault(rid, set()).add("direct")
                    owner_of.setdefault(rid, r)
        for r in requests:
            if r.deletion:
                r.home_files = {o.file_id for rid in r.resources for o in self.by_res[rid]
                                if o.keys & r.identity.strong_keys()}

        # learn the scheduler cadence from identifier-anchored runs, then build runs
        self.cal = calibrate(requests, self.act_by_res, self.is_workflow, owner_of, self.acts)
        self._build_chains()

        # score every (run, request) pairing
        dels = [r for r in requests if r.deletion]
        cand = defaultdict(dict)  # run index -> {request index: score}
        for ri in range(len(self.runs)):
            members = self._members(ri)
            rids = {m["resource_id"] for m in members}
            owners = {id(owner_of[x]) for x in rids if x in owner_of}
            t0 = min(m["_t"] for m in members)
            t1 = max(m["_t"] for m in members)
            for qi, r in enumerate(dels):
                if not (r.requested_at <= t0 and t1 <= r.reported_at + timedelta(hours=3)):
                    continue
                if owners and id(r) not in owners:
                    continue
                score = self._score(ri, rids, r, owner_of, t0)
                if score is not None:
                    cand[ri][qi] = score

        # 1) a run holding a record directly attributed to a request goes to that request
        assigned, has_account = {}, set()
        for ri in sorted(cand):
            qi, sc = max(cand[ri].items(), key=lambda kv: (kv[1], -kv[0]))
            if sc >= DIRECT:
                assigned[ri] = qi
                if self.runs[ri]["account"]:
                    has_account.add(qi)
        # 2) the rest: exact maximum-weight assignment - at most one account-opening run and one
        #    loose run per request, and every run to at most one request
        for kind in ("account", "loose"):
            edges = {}
            for ri, opts in cand.items():
                if ri in assigned or bool(self.runs[ri]["account"]) != (kind == "account"):
                    continue
                for qi, sc in opts.items():
                    if kind == "account" and qi in has_account:
                        continue
                    edges[(ri, qi)] = sc + 1000.0  # attributing beats leaving a run unassigned
            assigned.update(max_weight_assignment(edges))
        # 3) flag genuine near-ties.  The output contract has no "undecided" status and dropping the
        #    record would hide data from the audit, so the best-supported attribution is kept and the
        #    case is listed for a reviewer (review_queue.csv).
        for ri, qi in sorted(assigned.items()):
            alts = [(sc, q) for q, sc in cand[ri].items() if q != qi]
            if alts:
                sc, q = max(alts)
                if abs(cand[ri][qi] - sc) < AMBIGUITY_MARGIN:
                    self.review.append(dict(
                        case_id=dels[qi].case_id, reason="workflow_run_tie",
                        detail=f"run {sorted({m['resource_id'] for m in self._members(ri)})} also fits "
                               f"{dels[q].case_id} (score {cand[ri][qi]:.2f} vs {sc:.2f})"))
        for ri, qi in sorted(assigned.items()):
            r = dels[qi]
            how = "workflow" if cand[ri][qi] >= DIRECT else "workflow_timing"  # anchored run vs timing alone
            for m in self._members(ri):
                x = m["resource_id"]
                if x in owner_of and owner_of[x] is not r:
                    continue  # directly attributed to another request
                r.resources.setdefault(x, set()).add(how)

    def _score(self, ri, rids, r, owner_of, t0):
        cal, run = self.cal, self.runs[ri]
        score = DIRECT * sum(1 for x in rids if x in owner_of and owner_of[x] is r)
        ok_time = False
        if run["account"]:
            d = (run["account"]["_t"] - r.reported_at).total_seconds() / 60
            ok_time = any(lo <= d <= hi for lo, hi in cal.account_windows)
            expected = cal.status_map.get(run["account"]["reported_result"])
            if expected:
                score += 20 if expected == r.reported_status else -20
        if run["acts"]:
            d = (run["acts"][0]["_t"] - r.reported_at).total_seconds() / 60
            ok_time = ok_time or any(lo <= d <= hi for lo, hi in cal.action_windows)
        if not ok_time and score < DIRECT:
            return None
        score += 5 if ok_time else 0
        score += 10 * sum(1 for x in rids if any(o.file_id in r.home_files for o in self.by_res.get(x, [])))
        score -= abs((t0 - r.reported_at).total_seconds()) / 1e6
        return score
