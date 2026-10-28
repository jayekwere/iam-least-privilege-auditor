"""Terminal interface. Live collection never writes IAM resources or credentials."""

import os
import re
import tempfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import boto3
import typer
import yaml
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from iam_auditor import __version__
from iam_auditor.collector import collect_accounts
from iam_auditor.config import load_config
from iam_auditor.models import Report, Severity, Snapshot
from iam_auditor.report import SEVERITY_ORDER, build_report, render
from iam_auditor.rules import evaluate

app = typer.Typer(
    no_args_is_help=True, add_completion=False, help="Read-only IAM least-privilege audit."
)


class Format(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"


class Partition(StrEnum):
    AWS = "aws"
    GOV = "aws-us-gov"
    CN = "aws-cn"


def emit(
    report: Report, output_format: Format, output: Path | None, fail_on: Severity | None
) -> None:
    content = render(report, output_format.value)
    if output is None:
        typer.echo(content, nl=False)
    else:
        # Real reports contain account metadata. Atomic files start with mode 0600.
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=output.parent,
                delete=False,
            ) as handle:
                temporary = handle.name
                handle.write(content)
            os.replace(temporary, output)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
    if report.status == "incomplete":
        raise typer.Exit(2)
    if fail_on and any(
        SEVERITY_ORDER[item.severity] <= SEVERITY_ORDER[fail_on] for item in report.findings
    ):
        raise typer.Exit(1)


def finish(
    snapshots: list[Snapshot],
    config_path: Path | None,
    now: datetime,
    demo: bool,
    output_format: Format,
    output: Path | None,
    fail_on: Severity | None,
) -> None:
    config = load_config(config_path)
    findings = [item for snapshot in snapshots for item in evaluate(snapshot, config, now)]
    emit(
        build_report(snapshots, findings, config, now, "demo" if demo else "live"),
        output_format,
        output,
        fail_on,
    )


def failure(error: Exception) -> None:
    # Never print raw SDK errors, which can contain real ARNs or request parameters.
    if isinstance(error, ClientError):
        detail = str(error.response.get("Error", {}).get("Code", "ClientError"))
    else:
        detail = type(error).__name__
    typer.echo(
        f"Audit could not complete: {detail}. Check configuration and permissions.", err=True
    )
    raise typer.Exit(2)


@app.command()
def demo(
    output_format: Annotated[Format, typer.Option("--format")] = Format.TABLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    fail_on: Annotated[Severity | None, typer.Option("--fail-on")] = None,
) -> None:
    """Audit a disposable Moto environment with fictional, fixed-date activity observations."""
    try:
        load_config(config)
        from iam_auditor.demo import DEMO_NOW, demo_snapshot

        finish([demo_snapshot()], config, DEMO_NOW, True, output_format, output, fail_on)
    except ImportError:
        typer.echo('Install demo dependencies: python -m pip install -e ".[demo]"', err=True)
        raise typer.Exit(2) from None
    except (
        OSError,
        ValueError,
        ValidationError,
        yaml.YAMLError,
        BotoCoreError,
        ClientError,
    ) as error:
        failure(error)


@app.command()
def audit(
    account: Annotated[
        list[str] | None, typer.Option("--account", help="Repeat for each account.")
    ] = None,
    role_name: Annotated[str | None, typer.Option("--role-name")] = None,
    external_id: Annotated[str | None, typer.Option("--external-id")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    region: Annotated[str, typer.Option("--region")] = "us-east-1",
    partition: Annotated[Partition, typer.Option("--partition")] = Partition.AWS,
    output_format: Annotated[Format, typer.Option("--format")] = Format.TABLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    fail_on: Annotated[Severity | None, typer.Option("--fail-on")] = None,
) -> None:
    """Audit the current session, or assume the same read-only role in explicit accounts."""
    accounts = account or []
    if bool(accounts) != bool(role_name):
        raise typer.BadParameter("Use --account and --role-name together.")
    if any(not re.fullmatch(r"[0-9]{12}", value) for value in accounts):
        raise typer.BadParameter("Each --account must contain 12 ASCII digits.")
    if role_name and not re.fullmatch(r"[A-Za-z0-9_+=,.@/-]{1,512}", role_name):
        raise typer.BadParameter("Invalid role name or path.")
    if external_id and not accounts:
        raise typer.BadParameter("--external-id requires --account and --role-name.")
    try:
        load_config(config)
        session = boto3.Session(profile_name=profile, region_name=region)
        snapshots = collect_accounts(session, accounts, role_name, external_id, partition.value)
        finish(snapshots, config, datetime.now(UTC), False, output_format, output, fail_on)
    except (
        OSError,
        ValueError,
        ValidationError,
        yaml.YAMLError,
        BotoCoreError,
        ClientError,
    ) as error:
        failure(error)


@app.command()
def schema() -> None:
    """Print the JSON Schema for dashboard integrations."""
    import json

    typer.echo(json.dumps(Report.model_json_schema(), indent=2, sort_keys=True))


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)
