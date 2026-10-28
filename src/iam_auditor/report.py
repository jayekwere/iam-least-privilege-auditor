"""Stable ordering, auditable suppressions, and three report renderers."""

import fnmatch
import json
from datetime import datetime
from io import StringIO
from typing import Literal

from rich.console import Console
from rich.table import Table

from iam_auditor.config import Config
from iam_auditor.models import AccountResult, Finding, Report, Severity, Snapshot, Summary

SEVERITY_ORDER = {severity: i for i, severity in enumerate(Severity)}


def build_report(
    snapshots: list[Snapshot],
    findings: list[Finding],
    config: Config,
    now: datetime,
    mode: Literal["live", "demo"],
) -> Report:
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.account_id, f.id)):
        reason = next(
            (
                item.reason
                for item in config.suppressions
                if item.rule_id == finding.rule_id
                and fnmatch.fnmatchcase(finding.resource, item.resource)
                and (item.account_id is None or item.account_id == finding.account_id)
                and (item.expires_on is None or item.expires_on >= now.date())
            ),
            None,
        )
        if reason:
            suppressed.append(finding.model_copy(update={"suppression_reason": reason}))
        else:
            active.append(finding)
    issues = [issue for snapshot in snapshots for issue in snapshot.issues]
    return Report(
        generated_at=now,
        mode=mode,
        status="incomplete" if issues else "complete",
        accounts=[
            AccountResult(
                account_id=snapshot.account_id,
                status="incomplete" if snapshot.issues else "complete",
                users=sum(p.kind == "user" for p in snapshot.principals),
                roles=sum(p.kind == "role" for p in snapshot.principals),
                policies=len(snapshot.policies),
            )
            for snapshot in snapshots
        ],
        summary=Summary(
            active=len(active),
            suppressed=len(suppressed),
            by_severity={
                severity: sum(f.severity == severity for f in active) for severity in Severity
            },
        ),
        findings=active,
        suppressed_findings=suppressed,
        collection_issues=issues,
    )


def cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>").replace("\r", "")


def render_markdown(report: Report) -> str:
    lines = [
        "# IAM least-privilege audit",
        "",
        f"Mode: {report.mode}. Status: {report.status}. Schema: {report.schema_version}.",
        f"Generated: {report.generated_at.isoformat()}.",
        f"Active findings: {report.summary.active}. Suppressed: {report.summary.suppressed}.",
        "",
        "Findings are review candidates, not proof of effective permissions or safe removal.",
        "",
        "| Severity | Rule | Resource | Evidence | Remediation | Suppression |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for finding in [*report.findings, *report.suppressed_findings]:
        values = [
            finding.severity.value,
            finding.rule_id.value,
            finding.resource,
            json.dumps(finding.evidence, sort_keys=True),
            finding.remediation,
            finding.suppression_reason or "",
        ]
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    if report.collection_issues:
        lines.extend(["", "## Incomplete collection", ""])
        for issue in report.collection_issues:
            lines.append(
                f"- {cell(issue.account_id)}: {cell(issue.resource)}, "
                f"{cell(issue.operation)}, {cell(issue.code)}."
            )
    return "\n".join(lines) + "\n"


def render_table(report: Report) -> str:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)
    console.print(
        f"IAM audit | {report.mode} | {report.status} | "
        f"{report.summary.active} active | {report.summary.suppressed} suppressed",
        markup=False,
    )
    table = Table("Severity", "Rule", "Resource", "Evidence", "Remediation", "Suppression")
    for finding in [*report.findings, *report.suppressed_findings]:
        # Text objects prevent AWS-controlled names from becoming terminal markup.
        from rich.text import Text

        table.add_row(
            *map(
                Text,
                [
                    finding.severity.value,
                    finding.rule_id.value,
                    finding.resource,
                    json.dumps(finding.evidence, sort_keys=True),
                    finding.remediation,
                    finding.suppression_reason or "",
                ],
            )
        )
    console.print(table)
    for issue in report.collection_issues:
        console.print(
            f"INCOMPLETE {issue.account_id} {issue.resource} {issue.operation}: {issue.code}",
            markup=False,
        )
    return stream.getvalue()


def render(report: Report, output_format: str) -> str:
    if output_format == "json":
        return report.model_dump_json(indent=2) + "\n"
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "table":
        return render_table(report)
    raise ValueError(f"Unsupported report format: {output_format}")
