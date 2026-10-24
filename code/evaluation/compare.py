"""Metrics comparing predicted rows with reference rows (same schema as output.csv)."""
from __future__ import annotations

import json
from collections import Counter

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def step_key(s):
    return tuple(s.get(f, "") for f in FIELDS)


def lcs(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[m][n]


def compare(pred: dict, gold: dict) -> dict:
    """pred/gold: case_id -> {'deletion_status': str, 'steps': [..]}"""
    m = Counter()
    per_case = {}
    for cid, g in gold.items():
        p = pred.get(cid, {"deletion_status": "MISSING", "steps": []})
        gs, ps = g["steps"], p["steps"]
        m["cases"] += 1
        m["status_ok"] += p["deletion_status"] == g["deletion_status"]
        exact = [step_key(s) for s in gs] == [step_key(s) for s in ps]
        m["exact_steps"] += exact
        gk = Counter(step_key(s) for s in gs)
        pk = Counter(step_key(s) for s in ps)
        tp = sum((gk & pk).values())
        m["gold_steps"] += len(gs)
        m["pred_steps"] += len(ps)
        m["tp_steps"] += tp
        # resource-level (which records/risks were found)
        gr = {(s["system_id"], s["resource_id"]) for s in gs}
        pr = {(s["system_id"], s["resource_id"]) for s in ps}
        m["gold_res"] += len(gr)
        m["pred_res"] += len(pr)
        m["tp_res"] += len(gr & pr)
        # field-level: align by position
        for i, s in enumerate(gs):
            for f in FIELDS + ["step_no"]:
                m[f"field_total_{f}"] += 1
                if i < len(ps) and ps[i].get(f) == s.get(f):
                    m[f"field_ok_{f}"] += 1
        # sequence similarity
        seq_g = [step_key(s) for s in gs]
        seq_p = [step_key(s) for s in ps]
        denom = max(len(seq_g), len(seq_p)) or 1
        m["seq_sum"] += lcs(seq_g, seq_p) / denom if (seq_g or seq_p) else 1.0
        per_case[cid] = dict(status_ok=p["deletion_status"] == g["deletion_status"], exact=exact,
                             pred_status=p["deletion_status"], gold_status=g["deletion_status"],
                             missing=[s for s in gs if step_key(s) not in pk],
                             extra=[s for s in ps if step_key(s) not in gk])
    n = m["cases"] or 1
    prec = m["tp_steps"] / (m["pred_steps"] or 1)
    rec = m["tp_steps"] / (m["gold_steps"] or 1)
    res = {
        "cases": m["cases"],
        "status_accuracy": m["status_ok"] / n,
        "exact_steps_accuracy": m["exact_steps"] / n,
        "step_precision": prec,
        "step_recall": rec,
        "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "resource_precision": m["tp_res"] / (m["pred_res"] or 1),
        "resource_recall": m["tp_res"] / (m["gold_res"] or 1),
        "sequence_similarity": m["seq_sum"] / n,
        "field_accuracy": {f: m[f"field_ok_{f}"] / (m[f"field_total_{f}"] or 1) for f in FIELDS + ["step_no"]},
    }
    return {"metrics": res, "per_case": per_case}


def load_rows(path) -> dict:
    import csv
    out = {}
    with open(path, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            out[r["case_id"]] = {"deletion_status": r["deletion_status"], "steps": json.loads(r["steps_json"])}
    return out
