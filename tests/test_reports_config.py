import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from iam_auditor.config import Config, Suppression, load_config
from iam_auditor.models import CollectionIssue, Finding, Report, RuleId, Severity, Snapshot
from iam_auditor.report import build_report, render


def finding(
    snapshot: Snapshot,
    rule: RuleId,
    severity: Severity,
    resource: str,
    title: str,
    evidence: dict[str, str],
    remediation: str,
    subject: str = "",
) -> Finding:
    return Finding(
        id="mock-" + severity.value + subject,
        rule_id=rule,
        severity=severity,
        account_id=snapshot.account_id,
        resource=resource,
        title=title,
        evidence=dict(evidence),
        remediation=remediation,
    )


NOW = datetime(2026, 1, 15, tzinfo=UTC)
ACCOUNT = "000000000000"


def test_formats_schema_and_severity_order() -> None:
    snapshot = Snapshot(account_id=ACCOUNT)
    findings = [
        finding(
            snapshot,
            RuleId.MISSING_MFA,
            severity,
            "fake-user",
            "Mock",
            {"note": "x|y\nz"},
            "Review the mock user",
            severity.value,
        )
        for severity in reversed(list(Severity))
    ]
    report = build_report([snapshot], findings, Config(), NOW, "demo")
    assert [item.severity for item in report.findings] == list(Severity)
    assert Report.model_validate_json(render(report, "json")) == report
    assert json.loads(render(report, "json"))["schema_version"] == "1.1.0"
    markdown = render(report, "markdown")
    assert "| critical | IAM006 |" in markdown
    assert "x\\|y" in markdown
    assert "Review the mock user" in render(report, "table")
    with pytest.raises(ValueError, match="Unsupported"):
        render(report, "csv")


def test_suppression_requires_reason_and_respects_scope_and_expiry() -> None:
    with pytest.raises(ValidationError, match="meaningful"):
        Suppression(rule_id=RuleId.MISSING_MFA, resource="*", reason=" ")
    snapshot = Snapshot(account_id=ACCOUNT)
    item = finding(snapshot, RuleId.MISSING_MFA, Severity.LOW, "fake-user", "Mock", {}, "Review")
    for extra, expected in [
        ({}, 1),
        ({"account_id": "111111111111"}, 0),
        ({"expires_on": "2026-01-14"}, 0),
        ({"expires_on": "2026-01-15"}, 1),
        ({"resource": "other-*"}, 0),
        ({"rule_id": "IAM001"}, 0),
    ]:
        suppression = {
            "rule_id": "IAM006",
            "resource": "fake-*",
            "reason": "Temporary mock exception",
        }
        suppression.update(extra)
        report = build_report(
            [snapshot],
            [item],
            Config.model_validate(
                {
                    "suppressions": [suppression],
                }
            ),
            NOW,
            "demo",
        )
        assert report.summary.suppressed == expected
        if expected:
            assert report.suppressed_findings[0].suppression_reason == "Temporary mock exception"
            assert "Temporary mock exception" in render(report, "markdown")


def test_incomplete_is_visible_in_all_formats() -> None:
    snapshot = Snapshot(
        account_id=ACCOUNT,
        issues=[
            CollectionIssue(
                account_id=ACCOUNT,
                resource="fake-user",
                operation="list_users",
                code="AccessDenied",
            )
        ],
    )
    report = build_report([snapshot], [], Config(), NOW, "live")
    assert report.status == "incomplete"
    assert report.accounts[0].status == "incomplete"
    for fmt in ["json", "markdown", "table"]:
        assert "AccessDenied" in render(report, fmt)


def test_configuration_validation(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("thresholds:\n  unused_days: 120\n", encoding="utf-8")
    assert load_config(path).thresholds.unused_days == 120
    path.write_text("", encoding="utf-8")
    assert load_config(path) == load_config(None)
    for data in [
        {"thresholds": {"unused_days": 401}},
        {"thresholds": {"key_unused_days": 0}},
        {"thresholds": {"unused_days": "90"}},
        {"typo": 1},
        {"trusted_accounts": ["not-an-account"]},
        {"trusted_accounts": ["٠" * 12]},
    ]:
        with pytest.raises(ValidationError):
            Config.model_validate(data)
    assert Config(trusted_accounts=[ACCOUNT]).trusted_accounts == [ACCOUNT]
