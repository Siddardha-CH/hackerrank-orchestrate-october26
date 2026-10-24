# Ghost Data Still Exists — deletion-audit agent

Solution for **HackerRank Orchestrate (October 2026)**. The full challenge statement is in
[`problem_statement.md`](./problem_statement.md); agent instructions are in [`AGENTS.md`](./AGENTS.md).

For every request in `dataset/deletion_requests.csv` the agent decides whether deletion was actually
requested, reconstructs who the subject is (current and historical identifiers), finds every copy of
their data across databases, replicas, logs, exports, search indexes, analytics, support, backups and
connectors, establishes the state of each copy **at `audit_at`**, applies `deletion_rules.csv`, and emits
findings, an ordered remediation plan and the verification checks — or, for a finished deletion, the
evidence-backed checks that prove it.

```
case_id,deletion_status,steps_json      ->  output.csv (518 rows, natural case_id order)
```

## Quick start

Requirements: Python 3.10+. `pypdf` is recommended for reading PDFs; without it the agent falls back to the
hash-keyed text cache in `code/audit/document_cache.json` and produces the identical `output.csv`.
No API key is needed to reproduce `output.csv`.

```bash
pip install -r code/requirements.txt
python code/main.py                     # writes ./output.csv
python code/evaluation/main.py          # metrics, custom cases, robustness, output validation -> code/evaluation/*.md
python -m unittest discover -s code/tests -t code   # unit tests (stdlib only)
```

Outputs: `output.csv` (submission) and `review_queue.csv` (cases a human should confirm, with the reason;
`python code/main.py --llm-review` adds a Claude second opinion to each row when `ANTHROPIC_API_KEY` is set).

Optional live model use (only for screenshots not in the cache / undecidable request texts):
`export ANTHROPIC_API_KEY=...` (`pip install anthropic`). Keys are read from the environment only.

## Results on the labelled samples (32 cases)

| Status accuracy | Exact `steps_json` | Step P / R / F1 | Sequence similarity |
|---|---|---|---|
| **100%** | **90.6%** | 100% / 98.4% / 99.2% | 97.8% |

The three remaining differences are gold steps about resource ids that appear in no participant-visible
file or activity. Details, six team-authored cases and the improvement log are in
[`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md); token/cost accounting is in
[`code/evaluation/usage_report.md`](code/evaluation/usage_report.md).

## How it works

```
requests ─┐
          ├─ intent.py      does the text authorise deletion? (multilingual rules, negation first; LLM fallback)
identities┤─ data.py        email -> user_id(s) via current snapshot + audit log; all historical emails/phones/hashes
          │
evidence ─┼─ evidence.py    94 files -> ~3.3k normalised Observations
          │                 SQL (sqlite, primary/replica/failover tables, inventory scope), JSON bundles & exports,
          │                 6 log dialects (trace-joined: lookup key on *_started -> resource on *_completed),
          │                 handover text, PDFs (pypdf), screenshots (vision.py, cached VLM extraction)
          │
activity ─┼─ engine.py      linking: (1) identifier match  (2) data-catalog alias links  (3) workflow runs
          │                 for records that no longer carry identifiers
          │  calibration.py  learns the workflow cadence from identifier-anchored runs (no constants)
          │  assignment.py   exact max-weight assignment of runs to requests; near-ties -> review queue
          │
rules ────┼─ policy.py      state at audit_at -> required action -> findings / remediation / verification
          └─ pipeline.py    ordering, serialisation, output.csv
```

### Key ideas

* **Claims vs. evidence.** `reported_status` and activity `reported_result` are never trusted as state.
  State comes from the most recent *admissible* capture (file `captured_at <= audit_at`); later files may
  help identify a record but are never cited.
* **Identity.** Request emails may be historical. The audit log yields every past email, phone and email
  hash; e.g. an attachment scan matching the subject's *old* phone number is found and deleted. Matching
  is exact and case-insensitive, so look-alikes such as `g.silva76.jr@…` are not attributed.
* **Records without identifiers.** Deleted accounts (404) and anonymised analytics carry no identifier.
  They are attributed through the deletion **workflow run** that touched them. The scheduler's cadence,
  the run-opener offsets, timing windows and the result/status mapping are **learned on every run** from
  runs whose records *are* linked by identifiers (`calibration.py`); nothing is fitted to sample labels,
  and on data without such regularity timing attribution switches itself off. Runs are scored (identifier
  anchored members, co-occurrence in the subject's evidence capture, timing) and assigned by an exact
  maximum-weight assignment across *all* participant-facing requests, so a record can never belong to two
  people. Genuine ties are kept as the best-supported answer and listed in `review_queue.csv`.
* **No COMPLETE without proof.** Every record's required final state needs admissible evidence; otherwise
  the case stays INCOMPLETE and is queued for review.
* **Absence proofs.** A capture covering a whole system (SQL dump, inventory scope, records-assurance
  snapshot) that omits a record proves it absent — used only when no capture shows the record.
* **Replica drift.** All copies inside one capture are combined: a record redacted on the primary but still
  exposed on a replica is still exposed.
* **Policy.** `deletion_rules.csv` is loaded at runtime: DELETE (profile, search, export, marketing,
  secondary identifiers, attachments), REDACT (support messages, tombstones, email logs), ANONYMIZE
  (analytics/telemetry), RETAIN (security audit, legal holds — verified present), backups are retained but
  restore is blocked, connectors are disabled.
* **Ordering.** Findings → remediation → verification; within a phase by the operation table, then
  `system_id`, `resource_id`. Flows are disabled and restores blocked before records are changed.
  Remediation/verification for INCOMPLETE cases carry empty `evidence_id`; COMPLETE checks cite evidence.

### Where AI is used

* **Screenshots** (`code/audit/vision.py`): a vision-language model (Claude) turns each application screen
  into structured records using `VISION_PROMPT`. Results are cached by image SHA-256 in
  `code/audit/vision_cache.json`, so the full run is deterministic and costs no tokens. The prompt is in
  `code/prompts/vision_extraction.md`.
* **Intent** (`code/audit/intent.py`): rules decide all 518 texts - an erasure verb counts only when it
  targets the account or the person's data, so a single-field edit is not a deletion. The prompt in
  `code/prompts/intent_classification.md` is used only when the rules are undecided; without a model the
  safe default is "no deletion".
* **Review** (`code/audit/review.py`): flagged cases can get a Claude second opinion
  (`code/prompts/case_review.md`); it is advisory and never changes `output.csv`.
* The reasoning core is deliberately deterministic: the evidence is mostly structured, and exact parsing
  is cheaper, reproducible and auditable.

## Layout

```
code/
  main.py                 CLI entry point
  requirements.txt
  audit/                  the agent (data, intent, evidence, vision, calibration, assignment, engine,
                          policy, pipeline, review)
  prompts/                model prompts (screenshot extraction, intent fallback, case review)
  tests/                  unit tests
  evaluation/
    main.py               evaluation workflow (samples, custom cases, output validation, reports)
    compare.py            metrics
    custom_cases.py       team-authored cases
    evaluation_report.md  generated report
    usage_report.md       generated token/cost report
output.csv                predictions for dataset/deletion_requests.csv
log.txt                   agent chat transcript (AGENTS.md format)
```

## Packaging

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```
