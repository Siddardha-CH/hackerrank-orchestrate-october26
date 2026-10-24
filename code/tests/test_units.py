"""Unit tests (stdlib unittest; run with `python -m unittest discover -s code/tests` from the repo root)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from audit.assignment import max_weight_assignment  # noqa: E402
from audit.evidence import Observation, _parse_log_line, observations_from_document_text  # noqa: E402
from audit.intent import classify  # noqa: E402
from audit.policy import Assessment, latest_state, plan  # noqa: E402


class IntentTests(unittest.TestCase):
    def test_deletion_requests(self):
        for t in ["Please erase the account linked to this email address.",
                  "I no longer use this account and would like it permanently deleted.",
                  "I changed the email on this account before deleting it.",
                  "Solicito la eliminación permanente de la cuenta asociada a este correo.",
                  "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
                  "Bitte löschen Sie mein Konto."]:
            self.assertTrue(classify(t)[0], t)

    def test_non_deletion_requests(self):
        for t in ["Please remove me from marketing lists only.",
                  "Can you tell me what personal information you hold about me? This is an information request, "
                  "not a request to erase it.",
                  "Please don't delete anything - I only need a copy of my data.",
                  "Please remove the old shipping address from my profile.",   # single-field correction
                  "My saved cart is gone since the update, can you restore it?"]:
            self.assertFalse(classify(t)[0], t)


class LogParserTests(unittest.TestCase):
    def test_dialects(self):
        lines = [
            '2026-02-03T05:54:19Z | WARN | integration_service | tr-1 | connector_heartbeat | resource_id="data_flow_1" enabled="true"',
            '2026-07-28T05:51:21Z [INFO] [account_service] [tr-2] profile_lookup_completed: resource_id="account_1" rows="0"',
            '2026-09-10T08:56:20Z {"service":"account_service","trace_id":"tr-3","resource_id":"account_2","event":"profile_lookup_completed"}',
            '2026-09-30T11:51:03Z requestId=tr-4 level=DEBUG function=profile_service message="resource_id=\\"account_3\\" event=\\"profile_lookup_completed\\""',
            '2026-08-22T10:51:17Z <15>1 node-1 account_service tr-5 - - level=DEBUG resource_id="account_4" event="profile_lookup_completed"',
        ]
        for line in lines:
            kv = _parse_log_line(line)
            self.assertIsNotNone(kv, line)
            self.assertIn("resource_id", kv, line)
            self.assertIn("event", kv, line)

    def test_document_aliases(self):
        obs = observations_from_document_text("Statement NST-2026-0718-1842 user_18 ingrid.dahl@outlook.com", "e1",
                                              "2026-07-18T11:00:00Z")
        self.assertTrue(any(o.resource_id == "alias:NST-2026-0718-1842" and "user_18" in o.keys for o in obs))


class PolicyTests(unittest.TestCase):
    def _o(self, fid, ts, table, present=True, exposed=False):
        return Observation(fid, ts, ts, "support_platform", "support_1", present=present, exposed=exposed, table=table)

    def test_replica_drift_any_copy_exposed(self):
        st = latest_state([self._o("f1", "2026-01-02T00:00:00Z", "primary", exposed=False),
                           self._o("f1", "2026-01-01T00:00:00Z", "replica_eu", exposed=True)])
        self.assertTrue(st["exposed"])

    def test_complete_requires_evidence(self):
        a = [Assessment("account_1", "account_service", "USER_PROFILE", "DELETE", False, "e1", True),
             Assessment("audit_record_1", "security_service", "SECURITY_AUDIT_LOG", "RETAIN", False, "", False, "none")]
        status, steps = plan(a)
        self.assertEqual(status, "INCOMPLETE")
        self.assertTrue(all(s["evidence_id"] == "" for s in steps))

    def test_ordering(self):
        a = [Assessment("search_1", "search_service", "SEARCH_INDEX_ENTRY", "DELETE", True, "e1", True),
             Assessment("data_flow_1", "integration_service", "DATA_FLOW", "DISABLE", True, "e1", True),
             Assessment("account_1", "account_service", "USER_PROFILE", "DELETE", False, "e1", True)]
        status, steps = plan(a)
        ops = [s["operation"] for s in steps]
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(ops[:2], ["REPORT_REMAINING_RECORD", "REPORT_ACTIVE_DATA_FLOW"])
        self.assertLess(ops.index("DISABLE_DATA_FLOW"), ops.index("DELETE_RECORD"))
        self.assertEqual([s["step_no"] for s in steps], list(range(1, len(steps) + 1)))


class AssignmentTests(unittest.TestCase):
    def test_exclusive_and_optimal(self):
        # greedy would give r1->a (10) and leave r2 unmatched; optimal is r1->b, r2->a (9 + 8)
        edges = {("r1", "a"): 10, ("r1", "b"): 9, ("r2", "a"): 8}
        self.assertEqual(max_weight_assignment(edges), {"r1": "b", "r2": "a"})

    def test_input_order_independent(self):
        e1 = {("x", 1): 5, ("y", 1): 5, ("y", 2): 3}
        e2 = dict(reversed(list(e1.items())))
        self.assertEqual(max_weight_assignment(e1), max_weight_assignment(e2))


if __name__ == "__main__":
    unittest.main()
