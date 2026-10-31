import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from typer.testing import CliRunner

from iam_auditor import __version__
from iam_auditor.cli import app
from iam_auditor.demo import DEMO_ACCOUNT
from iam_auditor.models import CollectionIssue, Report, Snapshot

runner = CliRunner()


@pytest.mark.parametrize("fmt", ["table", "json", "markdown"])
def test_demo_cli_real_moto_no_network(fmt: str) -> None:
    result = runner.invoke(app, ["demo", "--format", fmt])
    assert result.exit_code == 0, result.output
    if fmt == "json":
        report = Report.model_validate_json(result.output)
        assert report.summary.active == 19
        assert report.mode == "demo" and report.status == "complete"
        assert len({item.rule_id for item in report.findings}) == 7
    else:
        assert "IAM001" in result.output
        assert "IAM007" in result.output


def test_output_file_private_and_repeatable(tmp_path: Path) -> None:
    output = tmp_path / "private" / "report.json"
    for _ in range(2):
        result = runner.invoke(app, ["demo", "--format", "json", "--output", str(output)])
        assert result.exit_code == 0 and not result.output
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert len(list(output.parent.iterdir())) == 1
    assert json.loads(output.read_text())["summary"]["active"] == 19


def test_config_suppression_and_fail_thresholds(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        'suppressions:\n  - rule_id: IAM005\n    resource: "*"\n'
        '    reason: "Fictional demonstration exception"\n',
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["demo", "--format", "json", "--config", str(config), "--fail-on", "critical"]
    )
    assert result.exit_code == 0
    report = Report.model_validate_json(result.output)
    assert report.summary.suppressed == 5 and report.summary.active == 14
    assert runner.invoke(app, ["demo", "--fail-on", "high"]).exit_code == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ["--account", DEMO_ACCOUNT],
        ["--role-name", "MockAudit"],
        ["--account", "invalid", "--role-name", "MockAudit"],
        ["--account", DEMO_ACCOUNT, "--role-name", "bad role"],
        ["--external-id", "mock-id"],
        ["--format", "invalid"],
    ],
)
def test_bad_arguments_never_start_a_session(arguments: list[str]) -> None:
    with patch("iam_auditor.cli.boto3.Session") as session:
        assert runner.invoke(app, ["audit", *arguments]).exit_code == 2
        session.assert_not_called()


@pytest.mark.parametrize("content", ["thresholds: [bad]", "[bad", "unknown: true"])
def test_invalid_config_never_contacts_aws(tmp_path: Path, content: str) -> None:
    config = tmp_path / "invalid.yaml"
    config.write_text(content, encoding="utf-8")
    with patch("iam_auditor.cli.boto3.Session") as session:
        result = runner.invoke(app, ["audit", "--config", str(config)])
        assert result.exit_code == 2 and "could not complete" in result.output
        session.assert_not_called()
    assert runner.invoke(app, ["demo", "--config", str(config)]).exit_code == 2


def test_audit_live_orchestration_and_partial_exit(snapshot: Snapshot) -> None:
    with (
        patch("iam_auditor.cli.boto3.Session") as session,
        patch("iam_auditor.cli.collect_accounts", return_value=[snapshot]) as collect,
    ):
        result = runner.invoke(
            app,
            [
                "audit",
                "--account",
                DEMO_ACCOUNT,
                "--role-name",
                "MockAudit",
                "--profile",
                "mock",
                "--external-id",
                "mock-id",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        assert Report.model_validate_json(result.output).mode == "live"
        collect.assert_called_once_with(
            session.return_value, [DEMO_ACCOUNT], "MockAudit", "mock-id", "aws"
        )
    snapshot.issues.append(
        CollectionIssue(
            account_id=DEMO_ACCOUNT, resource="mock", operation="get", code="AccessDenied"
        )
    )
    with (
        patch("iam_auditor.cli.boto3.Session"),
        patch("iam_auditor.cli.collect_accounts", return_value=[snapshot]),
    ):
        result = runner.invoke(app, ["audit", "--format", "json", "--fail-on", "high"])
        assert result.exit_code == 2
        assert Report.model_validate_json(result.output).status == "incomplete"


@pytest.mark.parametrize(
    "error",
    [
        NoCredentialsError(),
        ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "sensitive"}}, "GetCallerIdentity"
        ),
    ],
)
def test_credentials_errors_do_not_print_provider_details(error: Exception) -> None:
    with patch("iam_auditor.cli.boto3.Session", side_effect=error):
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 2 and "sensitive" not in result.output


def test_output_failure_cleans_temporary_file(tmp_path: Path) -> None:
    with patch("iam_auditor.cli.os.replace", side_effect=OSError("mock-failure")):
        assert runner.invoke(app, ["demo", "-o", str(tmp_path / "report.json")]).exit_code == 2
    assert not list(tmp_path.iterdir())


def test_demo_extra_missing_error_is_actionable() -> None:
    with patch("iam_auditor.demo.demo_snapshot", side_effect=ImportError("moto")):
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 2 and ".[demo]" in result.output


def test_schema_version_and_help() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0 and json.loads(result.output) == Report.model_json_schema()
    assert runner.invoke(app, ["version"]).output.strip() == __version__
    assert "read-only role" in runner.invoke(app, ["audit", "--help"]).output


def test_demo_does_not_read_real_profile_or_mutate_environment() -> None:
    with patch.dict(os.environ, {"AWS_PROFILE": "mock-nonexistent-profile"}):
        before = dict(os.environ)
        assert runner.invoke(app, ["demo"]).exit_code == 0
        assert dict(os.environ) == before
