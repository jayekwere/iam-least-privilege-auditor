"""Versioned public report models and internal normalized AWS observations."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from iam_auditor import __version__


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleId(StrEnum):
    UNUSED_PERMISSIONS = "IAM001"
    STALE_KEYS = "IAM002"
    INACTIVE_IDENTITIES = "IAM003"
    WILDCARD_POLICIES = "IAM004"
    ADMIN_ACCESS = "IAM005"
    MISSING_MFA = "IAM006"
    EXTERNAL_TRUST = "IAM007"
    FEDERATED_TRUST = "IAM008"
    ANALYZER = "IAM009"


class Finding(Model):
    id: str
    rule_id: RuleId
    severity: Severity
    account_id: str
    resource: str
    title: str
    evidence: dict[str, JsonValue]
    remediation: str
    classification: Literal["observed_misconfiguration", "review_candidate"] = "review_candidate"
    suppression_reason: str | None = None


class CollectionIssue(Model):
    account_id: str
    resource: str
    operation: str
    code: str


class AccountResult(Model):
    account_id: str
    status: Literal["complete", "incomplete"]
    users: int
    roles: int
    policies: int


class Summary(Model):
    active: int
    suppressed: int
    by_severity: dict[Severity, int]


class Report(Model):
    schema_version: Literal["1.1.0"] = "1.1.0"
    tool_version: str = __version__
    generated_at: datetime
    mode: Literal["live", "demo"]
    status: Literal["complete", "incomplete"]
    accounts: list[AccountResult]
    summary: Summary
    findings: list[Finding]
    suppressed_findings: list[Finding]
    collection_issues: list[CollectionIssue]


class ServiceAccess(Model):
    namespace: str
    last_authenticated: datetime | None = None


class AccessKey(Model):
    fingerprint: str
    suffix: str
    status: str
    created_at: datetime
    last_used: datetime | None = None


class Principal(Model):
    arn: str
    name: str
    kind: Literal["user", "role"]
    created_at: datetime
    console_enabled: bool = False
    password_last_used: datetime | None = None
    role_last_used: datetime | None = None
    mfa_enabled: bool = False
    keys: list[AccessKey] = Field(default_factory=list)
    services: list[ServiceAccess] = Field(default_factory=list)
    advisor_complete: bool = False
    identity_complete: bool = True
    attached_policy_arns: list[str] = Field(default_factory=list)
    permissions_boundary: str | None = None
    trust: dict[str, JsonValue] = Field(default_factory=dict)


class Policy(Model):
    resource: str
    document: dict[str, JsonValue]
    source: Literal["customer-managed", "aws-managed", "inline"]


class Snapshot(Model):
    account_id: str
    principals: list[Principal] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)
    analyzer_findings: list[dict[str, JsonValue]] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)
