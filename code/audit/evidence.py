"""Evidence ingestion.

Every participant-facing evidence file (SQL snapshots, JSON records, logs,
plain-text handovers, PDFs and screenshots) is normalised into a flat list of
``Observation`` objects.  An observation says: *in file F, at time T, resource
R of system S was seen in state X, and it was linked to identifiers K*.

The rest of the pipeline never looks at raw files again; it reasons only over
observations, activities and identities.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable

from . import vision

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
ALIAS_RE = re.compile(r"\bNST-\d{4}-\d{4}-\d+\b|\b[\w-]+\.(?:pdf|zip|jpg|png)\b")
RID_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|"
    r"legal_hold|marketing|object|cache|email_delivery|telemetry)_\d+\b"
)

PII_FIELDS = {
    "full_name", "name", "email", "phone", "email_hash", "display_name",
    "requester_name", "requester_email", "requester_phone", "owner_email",
    "owner_phone", "customer_email", "matched_value",
}
LINK_FIELDS = PII_FIELDS | {
    "customer_reference", "subject_reference", "user_id", "subject_selector",
    "lookup_value", "lookup_key", "match_key", "subject_key", "scan_key",
    "subject_ref", "correlation_key", "query",
}

# Map service / data-store names that appear in evidence to canonical system ids.
SYSTEM_ALIASES = {
    "profile_service": "account_service",
    "support_replica": "support_platform",
    "attachment_preview": "support_platform",
    "object_storage": "support_platform",
}

PREFIX_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "marketing": "marketing_platform",
    "cache": "cache_service",
    "email_delivery": "email_delivery_service",
}


def system_for(resource_id: str) -> str:
    for prefix in sorted(PREFIX_SYSTEM, key=len, reverse=True):
        if resource_id.startswith(prefix + "_"):
            return PREFIX_SYSTEM[prefix]
    return "unknown"


@dataclass
class Observation:
    file_id: str
    captured_at: str            # file-level capture time (admissibility cut-off)
    ts: str                     # time the resource was observed
    system: str
    resource_id: str
    present: bool | None = True  # None = unknown
    exposed: bool | None = None  # direct identifiers still visible?
    enabled: bool | None = None  # data flows
    restore_allowed: bool | None = None  # backups
    category: str | None = None  # explicit data category if the evidence states it
    keys: set = field(default_factory=set)  # lower-cased identifiers linking to a subject
    hash_only: bool = False     # linked only through an email hash
    table: str = ""             # SQL table name (replica drift analysis)
    note: str = ""

    def link_keys(self) -> set:
        return self.keys


def _norm(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if s == "" or s.lower() in {"null", "none", "—", "-", "no direct identifier"}:
        return None
    return s


def _keys_from(values: Iterable) -> set:
    out = set()
    for v in values:
        v = _norm(v)
        if not v:
            continue
        lv = v.lower()
        out.add(lv)
        for m in EMAIL_RE.findall(v):
            out.add(m.lower())
        for m in USER_RE.findall(v):
            out.add(m.lower())
    return out


def _is_redacted(text) -> bool:
    t = _norm(text)
    return t is None or "[redacted]" in t.lower()


def _record_obs(file_id, captured_at, ts, system, rec: dict, table="", category=None) -> Observation:
    """Generic conversion of a structured record (JSON/SQL row) to an observation."""
    rid = rec.get("resource_id")
    system = SYSTEM_ALIASES.get(system, system) or system_for(rid)
    if system in (None, "", "unknown"):
        system = system_for(rid)
    exposed = False
    link_values = []
    for k, v in rec.items():
        if k in PII_FIELDS and _norm(v) is not None and not _is_redacted(v):
            exposed = True
        if k in LINK_FIELDS:
            link_values.append(v)
    # nested search documents
    doc = rec.get("document")
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k in PII_FIELDS and _norm(v) is not None:
                exposed = True
            if k in LINK_FIELDS:
                link_values.append(v)
    # free text (support conversations) may embed identifiers
    text = rec.get("message_text")
    if text is not None:
        if not _is_redacted(text) and (EMAIL_RE.search(text) or re.search(r"\+\d", text)):
            exposed = True
        link_values.append(text)
    obs = Observation(file_id, captured_at, ts or captured_at, system, rid, present=True,
                      exposed=exposed, table=table, category=category)
    if "enabled" in rec:
        obs.enabled = str(rec["enabled"]).lower() in {"1", "true"}
    if "restore_allowed" in rec:
        obs.restore_allowed = str(rec["restore_allowed"]).lower() in {"1", "true"}
    if "download_available" in rec:
        obs.note = f"download_available={rec['download_available']}"
    if "account_status" in rec:
        obs.note = f"account_status={rec['account_status']}"
    obs.keys = _keys_from(link_values)
    if rec.get("file_name") or table.endswith("attachments") or "attachment" in table:
        obs.category = obs.category or "SUPPORT_ATTACHMENT"
        obs.keys |= _keys_from([rec.get("uploaded_by")])
    return obs


# Explicit "record_type/result" observations (handover notes, manifests, ledgers, lookups)
RESULT_STATE = {
    "FOUND": dict(present=True),
    "NOT_FOUND": dict(present=False),
    "IDENTIFIABLE": dict(present=True, exposed=True),
    "ANONYMIZED": dict(present=True, exposed=False),
    "REDACTED": dict(present=True, exposed=False),
    "ACTIVE": dict(present=True),
    "BLOCKED": dict(present=True),
    "DISABLED": dict(present=True),
}


def _result_obs(file_id, captured_at, ts, system, rid, record_type, result, subject) -> Observation:
    st = dict(RESULT_STATE.get(result, {}))
    obs = Observation(file_id, captured_at, ts or captured_at, SYSTEM_ALIASES.get(system, system), rid,
                      category=record_type, **st)
    if record_type == "DATA_FLOW":
        obs.enabled = result == "ACTIVE"
    if record_type == "BACKUP_ARCHIVE":
        obs.restore_allowed = result == "ACTIVE"
    if record_type in {"SUPPORT_MESSAGE", "ANALYTICS_PROFILE", "ACCOUNT_TOMBSTONE"} and "exposed" not in st:
        obs.exposed = None
    if record_type in {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "SUPPORT_ATTACHMENT"} and result == "FOUND":
        obs.exposed = True
    obs.keys = _keys_from([subject])
    return obs


# --------------------------------------------------------------------------------------
# SQL
# --------------------------------------------------------------------------------------

def parse_sql(path, file_id, captured_at) -> list[Observation]:
    con = sqlite3.connect(":memory:")
    con.executescript(open(path, encoding="utf-8").read())
    out: list[Observation] = []
    tables = [t for (t,) in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = dict(con.execute("select origin_system, captured_at from snapshot_scope"))
    table_system = {
        "customer_profiles": "account_service",
        "customer_search_documents": "search_service",
        "customer_analytics_profiles": "analytics_platform",
        "support_records": "support_platform",
        "customer_exports": "export_service",
        "connector_subscriptions": "integration_service",
        "backup_restore_entries": "backup_service",
        "security_audit_records": "security_service",
    }
    for t in tables:
        if t == "snapshot_scope":
            continue
        cols = [r[1] for r in con.execute(f'pragma table_info("{t}")')]
        rows = [dict(zip(cols, r)) for r in con.execute(f'select * from "{t}"')]
        for row in rows:
            if "record_json" in row:
                rec = json.loads(row["record_json"])
                ts = row.get("updated_at") or captured_at
                out.append(_record_obs(file_id, captured_at, ts, row["origin_system"], rec, table=t))
            else:
                rid = row["resource_id"]
                system = table_system.get(t) or system_for(rid)
                if "source_resource_id" in row and row.get("source_resource_id"):
                    row = dict(row)
                ts = row.get("updated_at") or row.get("indexed_at") or captured_at
                o = _record_obs(file_id, captured_at, ts, system, row, table=t)
                if "source_resource_id" in row:
                    o.keys |= _keys_from([row["source_resource_id"]])
                out.append(o)
    # Coverage markers (absence by omission).  An inventory declares its scope explicitly; a replica
    # dump covers every system that has a table/rows in it.
    if not scope:
        named = {"customer_profiles_failover_replica": "account_service", "customer_profiles_primary": "account_service",
                 "search_documents_primary": "search_service"}
        systems = {o.system for o in out} | {named[t] for t in tables if t in named}
        scope = {sysname: captured_at for sysname in systems}
    for sysname, ts in scope.items():
        out.append(Observation(file_id, captured_at, ts, sysname, f"__scope__:{sysname}", present=None,
                               note="scope"))
    return out


# --------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------

def parse_json(path, file_id, captured_at) -> list[Observation]:
    d = json.load(open(path, encoding="utf-8"))
    out: list[Observation] = []
    if "snapshots" in d:
        for snap in d["snapshots"]:
            store, coll, ts = snap["data_store"], snap["collection"], snap["captured_at"]
            out.append(Observation(file_id, captured_at, ts, store, f"__scope__:{store}", present=None,
                                   note="scope", table=coll))
            for rec in snap["records"]:
                if "result" in rec:
                    out.append(_result_obs(file_id, captured_at, rec.get("recorded_at") or ts, rec["system"],
                                           rec["resource_id"], rec["record_type"], rec["result"],
                                           rec.get("lookup_value")))
                else:
                    out.append(_record_obs(file_id, captured_at, ts, store, rec, table=coll))
        return out
    if "service_exports" in d:
        for system, groups in d["service_exports"].items():
            for _, recs in groups.items():
                for rec in recs:
                    ts = rec.get("observed_at") or captured_at
                    rid = rec["resource_id"]
                    if "status_code" in rec:  # account profile lookups
                        prof = rec.get("profile")
                        o = Observation(file_id, captured_at, ts, system, rid,
                                        present=rec["status_code"] == 200)
                        if prof:
                            o.exposed = any(_norm(v) for v in prof.values())
                            o.keys = _keys_from(prof.values())
                        else:
                            o.exposed = False
                        out.append(o)
                    elif "hits" in rec:
                        docs = rec["hits"].get("documents", [])
                        for doc in docs:
                            o = _record_obs(file_id, captured_at, ts, system, doc)
                            o.keys |= _keys_from([rec.get("query")])
                            out.append(o)
                        if not docs:
                            out.append(Observation(file_id, captured_at, ts, system, rid, present=False,
                                                   keys=_keys_from([rec.get("query")])))
                    else:
                        out.append(_record_obs(file_id, captured_at, ts, system, rec))
        return out
    recs = d.get("records", [])
    coll = d.get("collection", "")
    src = d.get("source", "")
    ts0 = d.get("captured_at") or captured_at
    for rec in recs:
        if "result" in rec:
            out.append(_result_obs(file_id, captured_at, rec.get("recorded_at") or ts0, rec["system"],
                                   rec["resource_id"], rec["record_type"], rec["result"],
                                   rec.get("subject_reference")))
        else:
            system = {"user_export_store": "export_service",
                      "analytics_identity_store": "analytics_platform"}.get(src) or system_for(rec["resource_id"])
            o = _record_obs(file_id, captured_at, ts0, system, rec, table=coll)
            if "download_available" in rec and str(rec["download_available"]).lower() == "false":
                o.present = False
                o.note = "download_unavailable"
            out.append(o)
    return out


# --------------------------------------------------------------------------------------
# Logs
# --------------------------------------------------------------------------------------

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")
KV_RE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')


def _parse_log_line(line: str):
    m = TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    kv: dict = {}
    if rest.startswith("{"):
        try:
            kv = {k: str(v) for k, v in json.loads(rest).items()}
            kv.setdefault("service", kv.get("logger"))
        except json.JSONDecodeError:
            return None
    else:
        body = rest.replace('\\"', '"').lstrip("| ").strip()
        # bracketed format: [LEVEL] [service] [trace] event: k="v"
        mb = re.match(r"\[(\w+)\] \[([\w-]+)\] \[([\w-]+)\] (\w+):(.*)$", body)
        mp = re.match(r"(\w+) \| ([\w-]+) \| ([\w-]+) \| (\w+) \|(.*)$", body)
        ms = re.match(r"<\d+>\d+ \S+ ([\w-]+) ([\w-]+) - - (.*)$", body)
        if mb:
            kv.update(level=mb.group(1), service=mb.group(2), trace_id=mb.group(3), event=mb.group(4))
            body = mb.group(5)
        elif mp:
            kv.update(level=mp.group(1), service=mp.group(2), trace_id=mp.group(3), event=mp.group(4))
            body = mp.group(5)
        elif ms:
            kv.update(service=ms.group(1), trace_id=ms.group(2))
            body = ms.group(3)
        for k, q, u in KV_RE.findall(body):
            kv[k] = q if u == "" else u
        if "function" in kv and "service" not in kv:
            kv["service"] = kv["function"]
        if "requestId" in kv and "trace_id" not in kv:
            kv["trace_id"] = kv["requestId"]
    kv["_ts"] = ts
    return kv


def _bool(v):
    if v is None:
        return None
    return str(v).lower() in {"1", "true", "yes"}


def _log_event_obs(kv, file_id, captured_at, trace_keys) -> Observation | None:
    ev = kv.get("event", "")
    rid = kv.get("resource_id")
    ts = kv["_ts"]
    if ev == "record_lookup":
        return _result_obs(file_id, captured_at, ts, kv.get("system"), rid, kv.get("record_type"),
                           kv.get("result"), kv.get("subject_reference"))
    if not rid or not RID_RE.fullmatch(rid):
        return None
    system = system_for(rid)
    keys = set(trace_keys) | _keys_from([kv.get(k) for k in LINK_FIELDS if k in kv])
    o = Observation(file_id, captured_at, ts, system, rid, keys=keys, note=ev)
    if ev in {"profile_lookup_completed"}:
        rows = kv.get("rows")
        st = kv.get("http_status")
        o.present = (rows not in (None, "0")) if rows is not None else st == "200"
        o.exposed = o.present
    elif ev == "index_query_completed":
        o.present = kv.get("result", "hit") == "hit" and kv.get("total_hits", "1") != "0"
        o.exposed = o.present
    elif ev in {"message_pii_scan"}:
        o.present, o.exposed, o.category = True, True, "SUPPORT_MESSAGE"
    elif ev in {"attachment_pii_scan"}:
        o.present, o.exposed, o.category = True, True, "SUPPORT_ATTACHMENT"
    elif ev == "support_ticket_read_completed":
        o.present = True
        o.exposed = any(_norm(kv.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
    elif ev == "message_read":
        o.present = True
        o.exposed = not _is_redacted(kv.get("message_text"))
        o.category = "SUPPORT_MESSAGE"
    elif ev in {"analytics_profile_read_completed", "analytics_profile_read"}:
        o.present = True
        di = kv.get("direct_identifiers")
        o.exposed = (di not in (None, "0")) if di is not None else any(
            _norm(kv.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
    elif ev == "analytics_identity_scan":
        o.present, o.exposed = True, True
    elif ev == "contact_lookup_completed":
        o.present = kv.get("rows", "1") != "0"
        o.exposed = o.present
        ck = (kv.get("correlation_key") or "").lower()
        if HASH_RE.fullmatch(ck):
            o.hash_only = True
            o.category = "SECONDARY_IDENTIFIER"
    elif ev == "audit_record_read_completed":
        o.present = kv.get("rows", "1") != "0"
    elif ev in {"connector_config_read_completed", "connector_config_loaded", "connector_heartbeat"}:
        o.present = True
        o.enabled = _bool(kv.get("enabled"))
        if ev == "connector_heartbeat" and kv.get("scheduler_registered") is not None:
            o.enabled = _bool(kv.get("enabled")) and _bool(kv.get("scheduler_registered"))
    elif ev == "restore_policy_read_completed":
        o.present = kv.get("archive_present", "true") == "true"
        o.restore_allowed = _bool(kv.get("restore_allowed"))
    elif ev == "restore_candidate_evaluated":
        o.present = True
        o.restore_allowed = _bool(kv.get("eligible")) and not _bool(kv.get("deletion_block"))
    elif ev == "restore_authorization_completed":
        o.present = True
        o.restore_allowed = kv.get("decision") != "deny"
    elif ev in {"export_download_check_completed", "export_metadata_read_completed"}:
        o.present = _bool(kv.get("available")) is not False
        o.exposed = o.present
    elif ev == "retained_order_loaded":
        o.present, o.category = True, "LEGAL_HOLD_RECORD"
    elif ev in {"contact_query_completed", "contact_lookup_completed"}:
        o.present = kv.get("rows", "1") != "0"
        o.exposed = o.present
    elif ev == "deletion_marker_check":
        o.present = _bool(kv.get("marker_found")) is False
        o.exposed = o.present
    elif ev in {"thumbnail_failed"}:
        return None
    else:
        o.present = None
    return o


TRACE_KEY_FIELDS = ("lookup_key", "match_key", "subject_key", "scan_key", "subject_ref", "correlation_key")


def parse_log(path, file_id, captured_at) -> list[Observation]:
    lines = [kv for kv in (_parse_log_line(l) for l in open(path, encoding="utf-8")) if kv]
    trace_keys: dict[str, set] = {}
    for kv in lines:
        tid = kv.get("trace_id")
        if tid and any(k in kv for k in TRACE_KEY_FIELDS) and kv.get("event", "").endswith("_started"):
            trace_keys.setdefault(tid, set()).update(_keys_from([kv[k] for k in TRACE_KEY_FIELDS if k in kv]))
    out = []
    for kv in lines:
        o = _log_event_obs(kv, file_id, captured_at, trace_keys.get(kv.get("trace_id"), set()))
        if o:
            out.append(o)
    return out


def parse_text_handover(path, file_id, captured_at) -> list[Observation]:
    out = []
    for line in open(path, encoding="utf-8"):
        parts = [p.strip() for p in line.strip().lstrip("-").split("|")]
        if len(parts) == 6 and RID_RE.fullmatch(parts[2]):
            ts, system, rid, rtype, result, subject = parts
            out.append(_result_obs(file_id, captured_at, ts, system, rid, rtype, result, subject))
    return out


# --------------------------------------------------------------------------------------
# Documents (PDF) and images
# --------------------------------------------------------------------------------------

def pdf_text(path) -> str:
    try:
        import pypdf
    except ImportError:  # pragma: no cover
        return ""
    r = pypdf.PdfReader(path)
    return "\n".join(p.extract_text() or "" for p in r.pages)


def parse_pdf(path, file_id, captured_at) -> list[Observation]:
    text = pdf_text(path)
    return observations_from_document_text(text, file_id, captured_at)


def observations_from_document_text(text: str, file_id: str, captured_at: str) -> list[Observation]:
    """Business documents name resources and subjects; each resource mentioned is observed present
    and linked to every subject identifier in the same document (documents are single-subject) or,
    for tabular registers, in the same row."""
    out = []
    rows = [l for l in text.splitlines() if "|" in l]
    if rows:  # tabular register (e.g. legal retention register)
        for l in rows:
            keys = _keys_from([l])
            rids = RID_RE.findall(l)
            order = re.search(r"ORD-\d+", l)
            for rid in rids:
                out.append(Observation(file_id, captured_at, captured_at, system_for(rid), rid, keys=keys))
            if order and not rids:
                out.append(Observation(file_id, captured_at, captured_at, "legal_service", f"order:{order.group(0)}",
                                       keys=keys, category="LEGAL_HOLD_RECORD",
                                       note=l.strip()))
        if out:
            return out
    keys = _keys_from(EMAIL_RE.findall(text) + USER_RE.findall(text))
    for alias in sorted(set(ALIAS_RE.findall(text))):
        out.append(Observation(file_id, captured_at, captured_at, "unknown", f"alias:{alias}", present=True,
                               exposed=bool(keys), keys=set(keys), note="document"))
    for rid in sorted(set(RID_RE.findall(text))):
        o = Observation(file_id, captured_at, captured_at, system_for(rid), rid, present=True, keys=set(keys))
        if rid.startswith("support_") and re.search(r"\.pdf|attachment", text, re.I):
            o.category = "SUPPORT_ATTACHMENT"
            o.exposed = True
        out.append(o)
    return out


def parse_image(path, file_id, captured_at, root) -> list[Observation]:
    rec = vision.extract(path, root)
    out = []
    for r in rec.get("records", []):
        rid = r.get("resource_id") or f"alias:{r.get('alias')}"
        o = Observation(file_id, captured_at, r.get("observed_at") or captured_at, r.get("system") or system_for(rid),
                        rid, present=r.get("present", True), exposed=r.get("exposed"),
                        enabled=r.get("enabled"), restore_allowed=r.get("restore_allowed"),
                        category=r.get("category"), keys=_keys_from(r.get("identifiers", [])), note="vision")
        out.append(o)
    return out


# --------------------------------------------------------------------------------------

def load_all(dataset_dir: str) -> tuple[list[Observation], dict]:
    manifest = {}
    with open(os.path.join(dataset_dir, "evidence_files.csv"), encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            manifest[row["file_id"]] = row
    obs: list[Observation] = []
    for fid, row in manifest.items():
        path = os.path.join(dataset_dir, row["file_path"])
        cap = row["captured_at"]
        ext = os.path.splitext(path)[1].lower()
        if not os.path.exists(path):
            continue
        if ext == ".sql":
            obs += parse_sql(path, fid, cap)
        elif ext == ".json":
            obs += parse_json(path, fid, cap)
        elif ext == ".log":
            obs += parse_log(path, fid, cap)
        elif ext == ".txt":
            obs += parse_text_handover(path, fid, cap)
        elif ext == ".pdf":
            obs += parse_pdf(path, fid, cap)
        elif ext in {".png", ".jpg", ".jpeg"}:
            obs += parse_image(path, fid, cap, dataset_dir)
    return obs, manifest
