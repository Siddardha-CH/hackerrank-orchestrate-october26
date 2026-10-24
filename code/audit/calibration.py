"""Self-calibration of workflow-timing parameters.

Records that were already de-identified carry no identifier, so they are attributed through the
deletion workflow run that touched them (see engine.py).  Rather than hard-coding the scheduler's
cadence, the parameters are *learned from the data on every run*, using only anchors proven by
identifiers (no sample answer is used):

stage 1 - follow-up cadence
    For each request, the workflow follow-up actions on records directly linked to it (email,
    user_id, phone, hash) are sorted; recurring intervals between consecutive anchored actions are
    the run cadence (sums of two intervals are rarer and fall below the frequency threshold).
stage 2 - run openers and timing windows
    Follow-up actions are chained with the learned cadence, so each anchored run is extended to its
    true first action (often a record that is already clean and therefore not anchored itself).  For
    requests whose account deletion is also anchored, (first action - account deletion) gives the
    opener gap; its seconds residue and range are learned per phase (first action before / after the
    report).  Where anchored account deletions and first actions fall relative to ``reported_at``
    gives the timing windows.
stage 3 - status consistency
    Which ``reported_result`` of the anchored account deletion co-occurs with which
    ``reported_status`` of the request (kept only for an >= 80% majority).

If the data has no anchors (e.g. produced by a different system) the learned lists are empty and
workflow attribution switches itself off, leaving identifier linking intact - the agent degrades to
"state unknown" rather than guessing.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field


# One explicit prior, used in addition to the learned windows: an event logged within 15 minutes of
# the workflow's own report is part of that report (too few identifier anchors exist for this case
# to be learned).  It is reported separately from learned values in the evaluation report.
REPORT_PRIOR = (-15.0, 15.0)


@dataclass
class Calibration:
    chain_gaps: list = field(default_factory=list)        # seconds
    gap_tolerance: int = 3
    opener: dict = field(default_factory=dict)            # phase -> dict(residue, lo, hi, n)
    residue_tolerance: int = 2
    account_windows: list = field(default_factory=list)   # [(lo, hi)] minutes relative to reported_at
    action_windows: list = field(default_factory=list)    # [(lo, hi)] minutes relative to reported_at
    status_map: dict = field(default_factory=dict)        # reported_result -> reported_status
    anchors: dict = field(default_factory=dict)           # counts, for the report

    def summary(self) -> dict:
        return dict(chain_gaps=self.chain_gaps, opener=self.opener, account_windows=self.account_windows,
                    action_windows=self.action_windows, status_map=self.status_map, anchors=self.anchors,
                    prior_window=REPORT_PRIOR)


def _clusters(values, tol, min_count):
    out = []
    for v in sorted(values):
        if out and v - out[-1][-1] <= tol:
            out[-1].append(v)
        else:
            out.append([v])
    return [(Counter(c).most_common(1)[0][0], len(c)) for c in out if len(c) >= min_count]


def _intervals(values, split=10.0, margin=5.0, min_count=3):
    """Dense intervals of offsets (a new interval starts after an empty stretch > `split` minutes)."""
    out = []
    for v in sorted(values):
        if out and v - out[-1][-1] <= split:
            out[-1].append(v)
        else:
            out.append([v])
    return [(round(c[0] - margin, 1), round(c[-1] + margin, 1)) for c in out if len(c) >= min_count]


def _merge(intervals):
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def chain_followups(acts, gaps, tol):
    """Union-find chaining of follow-up activities whose gap matches a cadence interval."""
    acts = sorted(acts, key=lambda a: (a["_t"], a["activity_id"]))
    parent = {a["activity_id"]: a["activity_id"] for a in acts}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    max_gap = max(gaps, default=0) + tol
    for i, a in enumerate(acts):
        for b in acts[i + 1:]:
            g = (b["_t"] - a["_t"]).total_seconds()
            if g > max_gap:
                break
            if any(abs(g - x) <= tol for x in gaps):
                parent[find(b["activity_id"])] = find(a["activity_id"])
    groups = defaultdict(list)
    for a in acts:
        groups[find(a["activity_id"])].append(a)
    return {aid: groups[find(aid)] for aid in parent}


def calibrate(requests, act_by_res, is_workflow, owner_of, all_acts) -> Calibration:
    cal = Calibration()
    anchored = defaultdict(list)  # request id -> anchored workflow activities
    reqs = {}
    for rid, req in owner_of.items():
        for a in act_by_res.get(rid, []):
            if is_workflow(a) and req.requested_at <= a["_t"]:
                anchored[id(req)].append(a)
                reqs[id(req)] = req

    def is_account(a):
        return a["resource_id"].startswith("account_")

    # stage 1: cadence between consecutive anchored follow-ups
    gaps = []
    for acts in anchored.values():
        follow = sorted((a for a in acts if not is_account(a)), key=lambda a: a["_t"])
        for a, b in zip(follow, follow[1:]):
            g = int((b["_t"] - a["_t"]).total_seconds())
            if 0 < g <= 3600:
                gaps.append(g)
    cl = _clusters(gaps, cal.gap_tolerance, 3)
    if cl:
        top = max(c for _, c in cl)
        cal.chain_gaps = sorted(v for v, c in cl if c >= max(3, top * 0.1))

    # stage 2: extend anchored runs to their true first action, learn openers and windows
    followups = [a for a in all_acts if is_workflow(a) and not is_account(a)]
    chain = chain_followups(followups, cal.chain_gaps, cal.gap_tolerance)
    opener = defaultdict(list)
    acct_offsets, act_offsets = [], []
    status_votes = defaultdict(Counter)
    for key, acts in anchored.items():
        req = reqs[key]
        accts = sorted((a for a in acts if is_account(a) and a["event_type"] == "DELETE_RECORD"), key=lambda a: a["_t"])
        follow = [a for a in acts if not is_account(a)]
        first = None
        if follow:
            members = {m["activity_id"]: m for a in follow for m in chain.get(a["activity_id"], [a])}
            first = min(members.values(), key=lambda m: (m["_t"], m["activity_id"]))
            act_offsets.append((first["_t"] - req.reported_at).total_seconds() / 60)
        if accts:
            ac = accts[0]
            acct_offsets.append((ac["_t"] - req.reported_at).total_seconds() / 60)
            status_votes[ac["reported_result"]][req.reported_status] += 1
            if first is not None:
                g = int((first["_t"] - ac["_t"]).total_seconds())
                if g > 0:
                    opener["pre" if first["_t"] <= req.reported_at else "post"].append(g)
    for phase, vals in sorted(opener.items()):
        res = Counter(v % 60 for v in vals).most_common(1)[0][0]
        close = [v for v in vals if min(abs(v % 60 - res), 60 - abs(v % 60 - res)) <= cal.residue_tolerance]
        if len(close) >= 3 and len(close) >= 0.6 * len(vals):
            cal.opener[phase] = dict(residue=res, lo=min(close) - 300, hi=max(close) + 300, n=len(close))
    cal.account_windows = _merge(_intervals(acct_offsets) + [REPORT_PRIOR])
    cal.action_windows = _merge(_intervals(act_offsets) + [REPORT_PRIOR])

    # stage 3: reported_result <-> reported_status consistency
    for result, votes in sorted(status_votes.items()):
        status, n = votes.most_common(1)[0]
        if n >= 3 and n >= 0.8 * sum(votes.values()):
            cal.status_map[result] = status
    cal.anchors = dict(requests_with_anchors=len(anchored), follow_up_gaps=len(gaps),
                       opener_pairs={k: len(v) for k, v in sorted(opener.items())},
                       account_offsets=len(acct_offsets), first_action_offsets=len(act_offsets))
    return cal
