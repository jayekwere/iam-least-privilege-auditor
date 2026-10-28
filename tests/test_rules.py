from datetime import timedelta
from typing import Any

import pytest

from iam_auditor.config import Config
from iam_auditor.demo import DEMO_ACCOUNT, DEMO_NOW, EXTERNAL_ACCOUNT, allow, trust
from iam_auditor.models import Policy, RuleId, ServiceAccess, Severity, Snapshot
from iam_auditor.rules import (
    RULES,
    admin_access,
    enforced_external_id,
    evaluate,
    external_trust,
    inactive_identities,
    missing_mfa,
    stale_keys,
    statements,
    strings,
    unused_permissions,
    wildcard_policies,
)


def test_every_rule_has_moto_seeded_positive(snapshot: Snapshot) -> None:
    assert not snapshot.issues
    assert {item.rule_id for item in evaluate(snapshot, Config(), DEMO_NOW)} == set(RuleId)
    assert len(RULES) == 7


def test_unused_service_threshold_and_observation_window(snapshot: Snapshot) -> None:
    principal = snapshot.principals[0]
    snapshot.principals = [principal]
    results = unused_permissions(snapshot, Config(), DEMO_NOW)
    assert len(results) == 1
    assert results[0].evidence["service"] == "s3"
    assert not unused_permissions(
        snapshot,
        Config.model_validate(
            {
                "thresholds": {"unused_days": 121},
            }
        ),
        DEMO_NOW,
    )
    principal.services = [ServiceAccess(namespace="s3")]
    assert unused_permissions(snapshot, Config(), DEMO_NOW)[0].evidence["last_attempt"] is None
    principal.created_at = DEMO_NOW
    assert not unused_permissions(snapshot, Config(), DEMO_NOW)
    principal.created_at = DEMO_NOW - timedelta(days=90)
    assert unused_permissions(snapshot, Config(), DEMO_NOW)
    principal.advisor_complete = False
    assert not unused_permissions(snapshot, Config(), DEMO_NOW)


def test_key_unused_rotation_and_inactive_controls(snapshot: Snapshot) -> None:
    key = snapshot.principals[0].keys[0]
    results = stale_keys(snapshot, Config(), DEMO_NOW)
    assert len(results) == 1 and results[0].severity == Severity.HIGH
    assert results[0].evidence["key_suffix"] == "0000"
    assert "MOCK-ACCESS-KEY-DEMO" not in results[0].model_dump_json()
    key.last_used = DEMO_NOW
    assert stale_keys(snapshot, Config(), DEMO_NOW)[0].severity == Severity.MEDIUM
    key.created_at = DEMO_NOW - timedelta(days=89)
    assert not stale_keys(snapshot, Config(), DEMO_NOW)
    key.created_at = DEMO_NOW - timedelta(days=90)
    assert stale_keys(snapshot, Config(), DEMO_NOW)
    key.status = "Inactive"
    assert not stale_keys(snapshot, Config(), DEMO_NOW)


def test_inactive_uses_all_activity_and_skips_incomplete(snapshot: Snapshot) -> None:
    assert len(inactive_identities(snapshot, Config(), DEMO_NOW)) == 3
    principal = snapshot.principals[0]
    snapshot.principals = [principal]
    principal.password_last_used = DEMO_NOW
    assert not inactive_identities(snapshot, Config(), DEMO_NOW)
    principal.password_last_used = None
    principal.keys[0].last_used = DEMO_NOW
    assert not inactive_identities(snapshot, Config(), DEMO_NOW)
    principal.keys[0].last_used = None
    principal.role_last_used = DEMO_NOW
    assert not inactive_identities(snapshot, Config(), DEMO_NOW)
    principal.role_last_used = None
    principal.identity_complete = False
    assert not inactive_identities(snapshot, Config(), DEMO_NOW)
    principal.identity_complete = True
    principal.advisor_complete = False
    assert not inactive_identities(snapshot, Config(), DEMO_NOW)


def test_wildcards_cover_managed_group_and_identity_inline(snapshot: Snapshot) -> None:
    results = wildcard_policies(snapshot, Config(), DEMO_NOW)
    assert {row.evidence["source"] for row in results} == {"customer-managed", "inline"}
    assert any(":group/" in row.resource for row in results)
    assert any(":role/" in row.resource for row in results)
    snapshot.policies = [
        Policy(
            resource="mock",
            source="inline",
            document={
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "mock-bucket/*"},
                ]
            },
        )
    ]
    assert not wildcard_policies(snapshot, Config(), DEMO_NOW)
    snapshot.policies[0].document = {
        "Statement": {
            "Effect": "Allow",
            "Action": ["*"],
            "Resource": "*",
            "Condition": {"mock": "guard"},
        }
    }
    row = wildcard_policies(snapshot, Config(), DEMO_NOW)[0]
    assert row.severity == Severity.HIGH and row.evidence["condition_present"]


def test_admin_attachment_and_pass_role_scope(snapshot: Snapshot) -> None:
    rows = admin_access(snapshot, Config(), DEMO_NOW)
    assert any(row.resource.endswith("user/mock-alder") for row in rows)
    assert any(row.evidence.get("pass_role") and row.severity == Severity.HIGH for row in rows)
    principal = snapshot.principals[0]
    principal.attached_policy_arns = [f"arn:aws:iam::{DEMO_ACCOUNT}:policy/AdministratorAccess"]
    snapshot.principals = [principal]
    snapshot.policies = []
    assert not admin_access(snapshot, Config(), DEMO_NOW)
    for action, resource, expected in [
        ("iam:PassRole", f"arn:aws:iam::{DEMO_ACCOUNT}:role/mock-one", 0),
        ("iam:Pass*", f"arn:aws:iam::{DEMO_ACCOUNT}:role/mock-*", 1),
        ("s3:*", "*", 0),
        ("*", "arn:aws:s3:::mock-bucket/*", 0),
        ("IAM:*", "*", 1),
    ]:
        snapshot.policies = [
            Policy(resource="mock", source="inline", document=allow(action, resource))
        ]
        assert len(admin_access(snapshot, Config(), DEMO_NOW)) == expected
    doc = allow("iam:*")
    doc["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalTag/team": "mock"}}
    snapshot.policies = [Policy(resource="mock", source="inline", document=doc)]
    assert admin_access(snapshot, Config(), DEMO_NOW)[0].severity == Severity.HIGH


def test_mfa_console_and_programmatic_severity(snapshot: Snapshot) -> None:
    rows = missing_mfa(snapshot, Config(), DEMO_NOW)
    assert [(row.resource.rsplit("/", 1)[-1], row.severity) for row in rows] == [
        ("mock-alder", Severity.HIGH),
        ("mock-birch", Severity.LOW),
    ]
    snapshot.principals[0].identity_complete = False
    assert len(missing_mfa(snapshot, Config(), DEMO_NOW)) == 1


@pytest.mark.parametrize(
    "condition, expected",
    [
        ({"StringEquals": {"sts:ExternalId": "mock-id"}}, True),
        ({"StringLike": {"sts:ExternalId": ["mock-id", "mock-other"]}}, True),
        ({"StringEqualsIfExists": {"sts:ExternalId": "mock-id"}}, False),
        ({"ForAllValues:StringEquals": {"sts:ExternalId": "mock-id"}}, False),
        ({"Null": {"sts:ExternalId": "false"}}, False),
        ({"StringLike": {"sts:ExternalId": "*"}}, False),
        ({"StringEquals": {"sts:ExternalId": ["mock-id", ""]}}, False),
        ({"StringEquals": {"other-key": "mock-id"}}, False),
        ({"StringEquals": []}, False),
        (None, False),
    ],
)
def test_external_id_must_be_mandatory_and_nonempty(condition: Any, expected: bool) -> None:
    assert enforced_external_id(condition) is expected


def test_external_trust_per_statement_and_approved_accounts(snapshot: Snapshot) -> None:
    rows = external_trust(snapshot, Config(), DEMO_NOW)
    assert {row.severity for row in rows} == {Severity.HIGH, Severity.LOW}
    assert not external_trust(snapshot, Config(trusted_accounts=[EXTERNAL_ACCOUNT]), DEMO_NOW)
    role = next(p for p in snapshot.principals if p.name == "mock-external-guarded")
    snapshot.principals = [role]
    role.trust = trust(DEMO_ACCOUNT)
    assert not external_trust(snapshot, Config(), DEMO_NOW)
    role.trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ]
    }
    assert external_trust(snapshot, Config(), DEMO_NOW)[0].severity == Severity.CRITICAL
    role.trust["Statement"] = [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "mock-id"}},
        },
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        },
        {"Effect": "Allow", "Principal": "*", "Action": "sts:TagSession"},
    ]
    assert external_trust(snapshot, Config(), DEMO_NOW)[0].severity == Severity.HIGH


def test_empty_and_malformed_statement_shapes() -> None:
    empty = Snapshot(account_id=DEMO_ACCOUNT)
    assert not evaluate(empty, Config(), DEMO_NOW)
    assert strings(None) == []
    assert strings([1, "iam:*"]) == ["iam:*"]
    assert list(statements({"Statement": 1})) == []
    assert list(statements({"Statement": [None, {"Effect": "Deny"}]})) == []


def test_finding_ids_are_stable_across_time(snapshot: Snapshot) -> None:
    first = {item.id for item in evaluate(snapshot, Config(), DEMO_NOW)}
    second = {item.id for item in evaluate(snapshot, Config(), DEMO_NOW + timedelta(days=1))}
    assert len(first) == 17 and first == second
