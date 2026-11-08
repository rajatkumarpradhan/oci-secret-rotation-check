# oci-secret-rotation-check

Offline auditor for **simplified OCI Vault secret metadata inventories**. Secrets that never rotate, rotations that silently stall, empty secret shells, and deletion windows that keep "deleted" secrets recoverable for weeks - this tool reads a static JSON inventory and reports them.

## What it is

A command-line review tool for secret metadata-as-data. Point it at an inventory JSON, get a severity-sorted findings list and an exit code suitable for CI gates.

- Runs 100% locally. No OCI SDK, no credentials, no network calls, and no secret content is ever read - the audit works on metadata only.
- Five rules (SEC001-SEC005), each unit-tested on positive and negative inputs.
- Exit code 2 when any HIGH finding exists; 0 when no HIGH finding exists; 1 on unreadable or malformed input.
- Ages are computed against the document's own `reference_time`, so audits are reproducible in CI.

## What it is NOT (honest limits)

- The input schema is a **simplified approximation** of Vault secret metadata. It is not the OCI API response shape, and the tool does not fetch inventories from a tenancy.
- Rotation-overdue (>90 days), stuck-rotation grace (1 day), and deletion-window review (>7 days) thresholds are local conventions, tunable in `rules.py`.
- The audit cannot verify that a rotation rule actually works, that consuming services picked up a new version, or that the secret value itself is strong - it reviews metadata posture only.
- Companion scope: this audits **secrets** (stored values). Key material rotation and protection modes are a separate concern (see oci-vault-key-audit).

## Input schema

```json
{
  "reference_time": "2026-11-09T00:00:00Z",
  "secrets": [
    {
      "name": "db-admin-password",
      "lifecycle_state": "ACTIVE",
      "rotation_rule": {"is_automatic": true, "interval_days": 30},
      "time_of_deletion": null,
      "versions": [
        {"version_number": 2, "stages": ["CURRENT", "LATEST"], "created_at": "2026-11-01T00:00:00Z"}
      ]
    }
  ]
}
```

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| SEC001 | HIGH | CURRENT content older than 90 days (or unparseable created_at); rotate the secret |
| SEC002 | MEDIUM | Active secret with no automatic rotation rule; rotation depends on memory |
| SEC003 | HIGH | LATEST version not promoted to CURRENT for over a day; rotation appears stuck |
| SEC004 | MEDIUM | Secret with no versions; consumers get nothing |
| SEC005 | LOW | Pending deletion scheduled more than 7 days out; long windows keep secrets recoverable |

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_secret_rotation_check samples/stale-secret-inventory.json
PYTHONPATH=src python3 -m oci_secret_rotation_check samples/hardened-secret-inventory.json
```

Or the end-to-end demo (stale inventory -> hardened inventory, with expected exit codes):

```sh
sh demo.sh
```

Expected demo output: the seeded inventory reports 2 high, 3 medium, 1 low findings and exits 2; the hardened inventory reports zero findings and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

18 unit tests cover every rule on positive and negative inputs, stage-promotion grace handling, deletion-window logic, sort order, malformed-input handling, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.
