"""Team-authored evaluation cases.

Each case is a request row run through the *real* dataset (so it competes for evidence and workflow
runs exactly like a production request) plus a check.  Checks are either exact expectations or
metamorphic relations against another case's answer - that lets us test identity resolution, intent
detection, decoys and the audit-time cut-off without inventing new ground truth.
"""

BASE_21 = dict(email="amara-okeke@proton.me", requested_at="2026-09-04T12:00:00Z", reported_status="COMPLETE",
               reported_at="2026-09-05T12:00:00Z", audit_at="2026-09-15T12:00:00Z")

CUSTOM_CASES = [
    {
        "id": "custom_historical_email",
        "what": "Same subject as case_93 but the request uses the *current* email (case_93 used the historical "
                "one from user_audit_log). Identity resolution must give the identical answer.",
        "row": dict(case_id="custom_01", email="t.lima58@yahoo.com", requested_at="2026-08-11T06:00:00Z",
                    reported_status="PARTIALLY_COMPLETE", reported_at="2026-08-13T06:00:00Z",
                    audit_at="2026-09-01T06:00:00Z",
                    request_text="Please permanently delete the account associated with this email address."),
        "check": ("same_as_eval", "case_93"),
    },
    {
        "id": "custom_uppercase_email",
        "what": "sample case_21 with the email in upper case; matching must be case-insensitive.",
        "row": dict(case_id="custom_02", **{**BASE_21, "email": "AMARA-OKEKE@PROTON.ME"},
                    request_text="I deleted my account. Verify the profile is gone."),
        "check": ("same_as_gold", "case_21"),
    },
    {
        "id": "custom_negated_deletion",
        "what": "Deletion words used in a negated, access-only request must not authorise deletion.",
        "row": dict(case_id="custom_03", **BASE_21,
                    request_text="Please don't delete anything - I only need a copy of the data you hold about me."),
        "check": ("expect", {"deletion_status": "NOT_APPLICABLE", "steps": []}),
    },
    {
        "id": "custom_german_request",
        "what": "Deletion request in a language not present in the dataset (German).",
        "row": dict(case_id="custom_04", **BASE_21,
                    request_text="Bitte löschen Sie mein Konto und alle damit verbundenen personenbezogenen Daten."),
        "check": ("same_as_gold", "case_21"),
    },
    {
        "id": "custom_time_travel",
        "what": "case_21 audited *before* the readback capture (evidence_92, 2026-09-15) existed: the agent must "
                "not cite evidence captured after audit_at.",
        "row": dict(case_id="custom_05", **{**BASE_21, "audit_at": "2026-09-10T00:00:00Z"},
                    request_text="Please delete my account."),
        "check": ("no_future_evidence", None),
    },
    {
        "id": "custom_lookalike_decoy",
        "what": "Search console shows g.silva76.jr@gmail.com (search_1874) next to the subject g.silva76@gmail.com; "
                "the look-alike record must not be attributed to the subject.",
        "row": dict(case_id="custom_06", email="g.silva76@gmail.com", requested_at="2026-08-30T03:00:00Z",
                    reported_status="NOT_STARTED", reported_at="2026-08-31T21:00:00Z", audit_at="2026-09-02T08:00:00Z",
                    request_text="Please close my account and process the associated personal-data deletion."),
        "check": ("excludes_resource", "search_1874"),
    },
    {
        "id": "custom_field_edit_not_deletion",
        "what": "Interview failure case: 'remove' aimed at a single field ('remove the old shipping address from my "
                "profile') is a correction, not an account deletion.",
        "row": dict(case_id="custom_07", **BASE_21,
                    request_text="Please remove the old shipping address from my profile."),
        "check": ("expect", {"deletion_status": "NOT_APPLICABLE", "steps": []}),
    },
]
