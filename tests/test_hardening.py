from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from iam_auditor.analyzer import collect_analyzer
from iam_auditor.collector import Collector
from iam_auditor.config import Config, load_config
from iam_auditor.demo import DEMO_ACCOUNT, DEMO_NOW
from iam_auditor.models import Snapshot
from iam_auditor.rules import analyzer_evidence, federated_trust


def test_oidc_exact_and_unsafe_conditions(snapshot: Snapshot) -> None:
    role = next(p for p in snapshot.principals if p.kind == "role")
    snapshot.principals = [role]
    issuer = "token.actions.githubusercontent.com"
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Principal": {"Federated": f"arn:aws:iam::{DEMO_ACCOUNT}:oidc-provider/{issuer}"},
    }
    role.trust = {"Statement": [statement]}
    assert federated_trust(snapshot, Config(), DEMO_NOW)
    statement["Condition"] = {
        "StringEquals": {
            f"{issuer}:aud": "sts.amazonaws.com",
            f"{issuer}:sub": "repo:example/demo:ref:refs/heads/main",
        }
    }
    role.trust = {"Statement": [statement]}
    assert not federated_trust(snapshot, Config(), DEMO_NOW)
    statement["Condition"]["StringEquals"][f"{issuer}:sub"] = "*"
    role.trust = {"Statement": [statement]}
    assert federated_trust(snapshot, Config(), DEMO_NOW)


def test_analyzer_pages_errors_and_limits() -> None:
    client = Mock()
    snapshot = Snapshot(account_id=DEMO_ACCOUNT)
    row = {
        "id": "example",
        "resource": "example-role",
        "resourceType": "AWS::IAM::Role",
        "updatedAt": datetime(2026, 1, 1, tzinfo=UTC),
    }
    client.list_findings.side_effect = [{"findings": [row], "nextToken": "one"}, {"findings": []}]
    collect_analyzer(client, snapshot, "example-analyzer")
    assert len(analyzer_evidence(snapshot, Config(), DEMO_NOW)) == 1
    assert not snapshot.issues
    client.list_findings.side_effect = None
    client.list_findings.return_value = {"findings": [], "nextToken": "one"}
    collect_analyzer(client, snapshot, "example-analyzer", max_pages=1)
    assert snapshot.issues[-1].code == "PaginationLimitExceeded"
    collect_analyzer(client, snapshot, "example-analyzer")
    assert snapshot.issues[-1].code == "InvalidPaginationMarker"
    client.list_findings.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "List")
    collect_analyzer(client, snapshot, "example-analyzer")
    assert snapshot.issues[-1].code == "AccessDenied"


def test_advisor_page_limit_is_incomplete(snapshot: Snapshot) -> None:
    principal = snapshot.principals[0]
    principal.advisor_complete = False
    client = Mock()
    client.generate_service_last_accessed_details.return_value = {"JobId": "example"}
    client.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "IsTruncated": True,
        "Marker": "one",
    }
    collector = Collector(client, DEMO_ACCOUNT, max_pages=1)
    collector.service_access(principal)
    assert not principal.advisor_complete
    assert collector.snapshot.issues[0].code == "PaginationLimitExceeded"


@pytest.mark.parametrize("content", ["a: &a [*a]", "x" * 65537])
def test_bounded_yaml(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_config(path)


def test_published_schema_matches_sample() -> None:
    import json

    import jsonschema

    schema = json.loads(Path("docs/report.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads(Path("examples/demo-report.json").read_text()), schema)


def test_boundary_context_does_not_suppress_candidates(snapshot: Snapshot) -> None:
    from iam_auditor.rules import evaluate

    principal = snapshot.principals[0]
    principal.permissions_boundary = f"arn:aws:iam::{DEMO_ACCOUNT}:policy/example-boundary"
    findings = evaluate(snapshot, Config(), DEMO_NOW)
    owned = [f for f in findings if f.resource == principal.arn]
    assert owned
    assert all(f.evidence["boundary_effect"] == "not evaluated" for f in owned)


def test_analyzer_cli_integration() -> None:
    from unittest.mock import patch

    from typer.testing import CliRunner

    from iam_auditor.cli import app

    arn = f"arn:aws:access-analyzer:us-east-1:{DEMO_ACCOUNT}:analyzer/example"
    with (
        patch("iam_auditor.cli.boto3.Session"),
        patch("iam_auditor.cli.collect_accounts", return_value=[Snapshot(account_id=DEMO_ACCOUNT)]),
        patch("iam_auditor.cli.collect_analyzer") as collect,
    ):
        result = CliRunner().invoke(app, ["audit", "--analyzer-arn", arn, "--format", "json"])
    assert result.exit_code == 0, result.output
    collect.assert_called_once()


@pytest.mark.parametrize(
    "args",
    [
        ["--analyzer-arn", "invalid"],
        ["--account", DEMO_ACCOUNT, "--role-name", "example", "--external-id", "!"],
    ],
)
def test_new_cli_validation(args: list[str]) -> None:
    from typer.testing import CliRunner

    from iam_auditor.cli import app

    assert CliRunner().invoke(app, ["audit", *args]).exit_code == 2
