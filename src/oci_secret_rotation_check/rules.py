"""Audit rules for simplified OCI Vault secret metadata documents.

The input schema is a static, simplified JSON approximation of Vault secret
metadata (versions, stages, rotation rules, deletion schedules). It is NOT
the OCI API shape; see README.md. Ages are computed against the document's
own 'reference_time' so audits are reproducible. All analysis is offline.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

ROTATION_OVERDUE_DAYS = 90
DELETION_WINDOW_REVIEW_DAYS = 7


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    secret: str
    message: str


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _current_version(secret):
    for version in secret.get("versions") or []:
        if "CURRENT" in [s.upper() for s in version.get("stages") or []]:
            return version
    return None


def rule_stale_current(secret, reference_time):
    """SEC001: CURRENT secret content older than ROTATION_OVERDUE_DAYS."""
    name = secret.get("name", "<unnamed>")
    version = _current_version(secret)
    if version is None:
        return
    created = _parse_time(version.get("created_at"))
    if created is None:
        yield Finding("SEC001", "HIGH", name,
                      "CURRENT version has no parseable created_at; rotation age cannot be assessed")
        return
    age = (reference_time - created).days
    if age > ROTATION_OVERDUE_DAYS:
        yield Finding("SEC001", "HIGH", name,
                      f"CURRENT content is {age} days old (over {ROTATION_OVERDUE_DAYS}); rotate this secret")


def rule_no_rotation_rule(secret, reference_time):
    """SEC002: active secret without any rotation rule."""
    name = secret.get("name", "<unnamed>")
    if (secret.get("lifecycle_state") or "ACTIVE").upper() != "ACTIVE":
        return
    rotation = secret.get("rotation_rule")
    if not rotation or rotation.get("is_automatic") is not True:
        yield Finding("SEC002", "MEDIUM", name,
                      "no automatic rotation rule; rotation depends on someone remembering")


def rule_stuck_rotation(secret, reference_time):
    """SEC003: LATEST and CURRENT on different versions past a 1-day grace."""
    name = secret.get("name", "<unnamed>")
    current = _current_version(secret)
    latest = None
    for version in secret.get("versions") or []:
        if "LATEST" in [s.upper() for s in version.get("stages") or []]:
            latest = version
    if current is None or latest is None:
        return
    if current is latest or current.get("version_number") == latest.get("version_number"):
        return
    created = _parse_time(latest.get("created_at"))
    if created is not None and (reference_time - created) > timedelta(days=1):
        yield Finding("SEC003", "HIGH", name,
                      f"LATEST version {latest.get('version_number')} has not been promoted to CURRENT for over a day; rotation appears stuck")


def rule_empty_secret(secret, reference_time):
    """SEC004: secret with no versions at all (empty shell)."""
    if not (secret.get("versions") or []):
        yield Finding("SEC004", "MEDIUM", secret.get("name", "<unnamed>"),
                      "secret has no versions; anything reading it gets nothing")


def rule_long_deletion_window(secret, reference_time):
    """SEC005: pending deletion scheduled more than DELETION_WINDOW_REVIEW_DAYS out."""
    name = secret.get("name", "<unnamed>")
    deletion = _parse_time(secret.get("time_of_deletion"))
    if deletion is None:
        return
    remaining = (deletion - reference_time).days
    if remaining > DELETION_WINDOW_REVIEW_DAYS:
        yield Finding("SEC005", "LOW", name,
                      f"deletion is {remaining} days out (over {DELETION_WINDOW_REVIEW_DAYS}); long windows keep deleted secrets recoverable")


RULES = (rule_stale_current, rule_no_rotation_rule, rule_stuck_rotation, rule_empty_secret, rule_long_deletion_window)


def audit_document(document):
    reference_time = _parse_time(document.get("reference_time")) or datetime.now(timezone.utc)
    findings = []
    for secret in document.get("secrets") or []:
        if not isinstance(secret, dict):
            continue
        for rule in RULES:
            findings.extend(rule(secret, reference_time))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.secret, f.message))
