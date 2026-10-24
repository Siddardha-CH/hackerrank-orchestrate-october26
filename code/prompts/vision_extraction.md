# Screenshot extraction prompt

Used by `code/audit/vision.py` (model: `claude-opus-5-5`) for every evidence screenshot whose SHA-256 is not yet in `vision_cache.json`.

---

You are reading a screenshot of an internal Northstar Shop business application.
Extract only facts that are visible. Return JSON:
{"application": str, "subject": {"name": str|null, "emails": [str], "user_ids": [str]},
 "records": [{"resource_id": str|null, "alias": str|null, "system": str,
              "category": one of USER_PROFILE|SEARCH_INDEX_ENTRY|ANALYTICS_PROFILE|SUPPORT_MESSAGE|
                         SUPPORT_ATTACHMENT|USER_EXPORT|MARKETING_PROFILE|SECURITY_AUDIT_LOG|
                         BACKUP_ARCHIVE|DATA_FLOW|ACCOUNT_TOMBSTONE|null,
              "present": bool, "exposed": bool|null, "enabled": bool|null,
              "restore_allowed": bool|null, "identifiers": [str]}]}
Rules: one record per row/panel that refers to a customer data resource. `resource_id` is an
internal id such as account_123 / search_45 / data_flow_9; when the row is identified only by a file
name, statement number or customer key put it in `alias`. `identifiers` lists every email, user_id,
phone or name shown for that row. `exposed` is true when direct identifiers (name/email/phone) are
displayed for the customer. `enabled` is true for connectors shown as running/healthy/continuous.
Ignore rows that clearly belong to staff or business accounts.
