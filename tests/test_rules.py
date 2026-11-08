import unittest

from oci_secret_rotation_check.rules import audit_document

REF = "2026-11-09T00:00:00Z"


def doc(secrets):
    return {"reference_time": REF, "secrets": secrets}


def base_secret(**overrides):
    secret = {
        "name": "s",
        "lifecycle_state": "ACTIVE",
        "rotation_rule": {"is_automatic": True, "interval_days": 30},
        "versions": [
            {"version_number": 2, "stages": ["CURRENT", "LATEST"], "created_at": "2026-11-01T00:00:00Z"},
            {"version_number": 1, "stages": ["PREVIOUS"], "created_at": "2026-10-01T00:00:00Z"},
        ],
    }
    secret.update(overrides)
    return secret


def rule_ids(findings):
    return {f.rule_id for f in findings}


class TestSecretRules(unittest.TestCase):
    def test_clean_secret_has_no_findings(self):
        self.assertEqual(audit_document(doc([base_secret()])), [])

    def test_sec001_stale_current(self):
        secret = base_secret()
        secret["versions"][0]["created_at"] = "2026-01-01T00:00:00Z"
        self.assertIn("SEC001", rule_ids(audit_document(doc([secret]))))

    def test_sec001_fresh_current_ok(self):
        self.assertNotIn("SEC001", rule_ids(audit_document(doc([base_secret()]))))

    def test_sec001_unparseable_created_at(self):
        secret = base_secret()
        secret["versions"][0]["created_at"] = "not-a-date"
        self.assertIn("SEC001", rule_ids(audit_document(doc([secret]))))

    def test_sec002_no_rotation_rule(self):
        self.assertIn("SEC002", rule_ids(audit_document(doc([base_secret(rotation_rule=None)]))))

    def test_sec002_manual_rotation_rule(self):
        secret = base_secret(rotation_rule={"is_automatic": False})
        self.assertIn("SEC002", rule_ids(audit_document(doc([secret]))))

    def test_sec002_non_active_secret_skipped(self):
        secret = base_secret(rotation_rule=None, lifecycle_state="PENDING_DELETION")
        self.assertNotIn("SEC002", rule_ids(audit_document(doc([secret]))))

    def test_sec003_stuck_rotation(self):
        secret = base_secret()
        secret["versions"] = [
            {"version_number": 3, "stages": ["LATEST"], "created_at": "2026-11-05T00:00:00Z"},
            {"version_number": 2, "stages": ["CURRENT"], "created_at": "2026-11-01T00:00:00Z"},
        ]
        self.assertIn("SEC003", rule_ids(audit_document(doc([secret]))))

    def test_sec003_recent_latest_within_grace(self):
        secret = base_secret()
        secret["versions"] = [
            {"version_number": 3, "stages": ["LATEST"], "created_at": "2026-11-08T12:00:00Z"},
            {"version_number": 2, "stages": ["CURRENT"], "created_at": "2026-11-01T00:00:00Z"},
        ]
        self.assertNotIn("SEC003", rule_ids(audit_document(doc([secret]))))

    def test_sec004_empty_secret(self):
        self.assertIn("SEC004", rule_ids(audit_document(doc([base_secret(versions=[])]))))

    def test_sec005_long_deletion_window(self):
        secret = base_secret(time_of_deletion="2026-12-31T00:00:00Z")
        self.assertIn("SEC005", rule_ids(audit_document(doc([secret]))))

    def test_sec005_short_window_ok(self):
        secret = base_secret(time_of_deletion="2026-11-12T00:00:00Z")
        self.assertNotIn("SEC005", rule_ids(audit_document(doc([secret]))))

    def test_findings_sorted_high_first(self):
        secret = base_secret(rotation_rule=None)  # SEC002 MEDIUM
        secret["versions"][0]["created_at"] = "2026-01-01T00:00:00Z"  # SEC001 HIGH
        findings = audit_document(doc([secret]))
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "MEDIUM")

    def test_non_dict_entries_skipped(self):
        findings = audit_document({"reference_time": REF, "secrets": [None, "junk", base_secret()]})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
