"""Apply deletion_rules.csv to reconstructed resource states and plan ordered steps."""
from __future__ import annotations

from dataclasses import dataclass

from .data import parse_ts
from .engine import PREFIX_CATEGORY, prefix_of
from .evidence import Observation, system_for

# required action per data category (mirrors dataset/deletion_rules.csv; loaded and checked at runtime)
DEFAULT_ACTION = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE", "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT",
    "DATA_FLOW": "DISABLE",
}

OP_ORDER = [
    ("FINDING", "REPORT_REMAINING_RECORD"), ("FINDING", "REPORT_EXPOSED_PII"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW"), ("FINDING", "REPORT_RESTORE_RISK"),
    ("REMEDIATION", "DISABLE_DATA_FLOW"), ("REMEDIATION", "BLOCK_RESTORE"), ("REMEDIATION", "DELETE_RECORD"),
    ("REMEDIATION", "REDACT_RECORD"), ("REMEDIATION", "ANONYMIZE_RECORD"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT"), ("VERIFICATION", "VERIFY_RECORD_PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED"), ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"), ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"),
]
OP_RANK = {op: i for i, (_, op) in enumerate(OP_ORDER)}
OP_PHASE = {op: ph for ph, op in OP_ORDER}
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# action -> (finding op, remediation op, verification op)
ACTION_OPS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "BLOCK": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
    "RETAIN": (None, None, "VERIFY_RECORD_PRESENT"),
}


def load_rules(rules_rows) -> dict:
    actions = dict(DEFAULT_ACTION)
    for r in rules_rows:
        actions[r["data_category"]] = r["required_action"]
    return actions


@dataclass
class Assessment:
    rid: str
    system: str
    category: str
    action: str            # DELETE / REDACT / ANONYMIZE / DISABLE / BLOCK / RETAIN
    violation: bool        # finding needed
    evidence: str          # evidence id proving the current state ('' if none admissible)
    known: bool            # do we have admissible evidence of the state?
    proof: str = "explicit"  # explicit | omission | none


def categorize(rid: str, obs: list[Observation], acts: list[dict]) -> str:
    explicit = [o.category for o in obs if o.category]
    if any(o.hash_only for o in obs):
        return "SECONDARY_IDENTIFIER"
    if explicit:
        # most recent explicit category wins
        return explicit[-1]
    p = prefix_of(rid)
    cat = PREFIX_CATEGORY.get(p, "USER_PROFILE")
    if cat == "SUPPORT_MESSAGE":
        ops = [a["event_type"] for a in acts if a["source_system"] == "deletion_worker"]
        if ops and ops[-1] == "DELETE_RECORD":
            return "SUPPORT_ATTACHMENT"
    if cat == "ANALYTICS_PROFILE":
        ops = [a["event_type"] for a in acts if a["source_system"] == "deletion_worker"]
        if ops and ops[-1] == "DELETE_RECORD":
            return "SECONDARY_IDENTIFIER"
    return cat


def latest_state(adm: list[Observation]):
    """Collapse admissible observations into the state shown by the most recent capture.

    All copies of a record inside one capture (primary and replica tables of a SQL dump, several
    lines of one log) are combined: the record is present / exposed / enabled if *any* copy is."""
    if not adm:
        return None
    by_file: dict[str, list[Observation]] = {}
    for o in adm:
        by_file.setdefault(o.file_id, []).append(o)
    fid, obs = max(by_file.items(), key=lambda kv: (max(o.ts for o in kv[1]), kv[1][0].captured_at, kv[0]))
    obs.sort(key=lambda o: o.ts)
    st = dict(file_id=fid, ts=max(o.ts for o in obs),
              present=any(o.present for o in obs),
              exposed=any(o.exposed for o in obs if o.present),
              enabled=None, restore_allowed=None)
    en = [o.enabled for o in obs if o.enabled is not None]
    if en:
        st["enabled"] = any(en)
    ra = [o.restore_allowed for o in obs if o.restore_allowed is not None]
    if ra:
        st["restore_allowed"] = any(ra)
    return st


def assess(rid: str, obs_all: list[Observation], acts: list[dict], audit_at, rules: dict,
           omission=None, since=None) -> Assessment:
    adm = [o for o in obs_all if parse_ts(o.captured_at) <= audit_at and o.present is not None]
    category = categorize(rid, obs_all, acts)
    action = rules.get(category, "DELETE")
    system = (obs_all[-1].system if obs_all and obs_all[-1].system not in ("unknown", "") else None) or system_for(rid)
    if category == "DATA_FLOW":
        action = "DISABLE"
    if category == "BACKUP_ARCHIVE":
        action = "BLOCK"
    st = latest_state(adm)
    if action == "DELETE" and omission is not None and st is None:
        # no capture shows the record at all: a later capture of the whole system that omits it proves absence
        om = omission(rid, system, since, audit_at, {o.file_id for o in obs_all})
        if om:
            st = dict(file_id=om[1], ts=om[0], present=False, exposed=False, enabled=None, restore_allowed=None,
                      proof="omission")
    if st is None:
        return Assessment(rid, system, category, action, False, "", False, "none")
    ev = st["file_id"]
    if action == "DELETE":
        viol = st["present"]
    elif action in ("REDACT", "ANONYMIZE"):
        viol = st["present"] and st["exposed"]
    elif action == "DISABLE":
        viol = bool(st["enabled"])
    elif action == "BLOCK":
        viol = st["restore_allowed"] if st["restore_allowed"] is not None else st["present"]
    else:  # RETAIN
        viol = False
    return Assessment(rid, system, category, action, bool(viol), ev, True, st.get("proof", "explicit"))


def plan(assessments: list[Assessment]) -> tuple[str, list[dict]]:
    """COMPLETE requires positive, admissible evidence for *every* record's required final state.
    A case with no violation but a record whose state cannot be proven is not declared complete:
    it is INCOMPLETE with the outstanding checks (and goes to the review queue)."""
    violations = [a for a in assessments if a.violation]
    unproven = [a for a in assessments if not a.known]
    steps = []
    if violations or unproven or not assessments:
        status = "INCOMPLETE"
        for a in violations:
            f, r, _ = ACTION_OPS[a.action]
            steps.append((f, a.system, a.rid, a.evidence))
            steps.append((r, a.system, a.rid, ""))
        for a in assessments:
            steps.append((ACTION_OPS[a.action][2], a.system, a.rid, ""))
    else:
        status = "COMPLETE"
        for a in assessments:
            steps.append((ACTION_OPS[a.action][2], a.system, a.rid, a.evidence))
    steps.sort(key=lambda s: (OP_RANK[s[0]], s[1], s[2]))
    out = []
    for i, (op, system, rid, ev) in enumerate(steps, 1):
        out.append({"step_no": i, "phase": OP_PHASE[op], "system_id": system, "resource_id": rid,
                    "operation": op, "state": OP_STATE[op], "evidence_id": ev})
    return status, out
