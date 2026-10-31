"""Seven independent rules over normalized observations, without AWS calls or mutation."""

import fnmatch
import hashlib
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from iam_auditor.config import Config
from iam_auditor.models import Finding, Principal, RuleId, Severity, Snapshot


def days_since(value: datetime, now: datetime) -> int:
    return (now - value.replace(tzinfo=value.tzinfo or UTC)).days


def finding(
    snapshot: Snapshot,
    rule: RuleId,
    severity: Severity,
    resource: str,
    title: str,
    evidence: dict[str, Any],
    remediation: str,
    subject: str = "",
) -> Finding:
    identity = "\0".join([rule.value, snapshot.account_id, resource, subject])
    return Finding(
        id=hashlib.sha256(identity.encode()).hexdigest()[:24],
        rule_id=rule,
        severity=severity,
        account_id=snapshot.account_id,
        resource=resource,
        title=title,
        evidence=evidence,
        remediation=remediation,
        classification="observed_misconfiguration"
        if rule == RuleId.MISSING_MFA
        else "review_candidate",
    )


def unused_permissions(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for principal in snapshot.principals:
        if not principal.advisor_complete:
            continue
        for service in principal.services:
            observed = service.last_authenticated or principal.created_at
            if days_since(observed, now) < config.thresholds.unused_days:
                continue
            results.append(
                finding(
                    snapshot,
                    RuleId.UNUSED_PERMISSIONS,
                    Severity.MEDIUM,
                    principal.arn,
                    "Granted service has no recent recorded access attempt",
                    {
                        "service": service.namespace,
                        "threshold_days": config.thresholds.unused_days,
                        "last_attempt": service.last_authenticated.isoformat()
                        if service.last_authenticated
                        else None,
                        "observation": "Access Advisor service-level tracking window",
                    },
                    f"Review {service.namespace} with the owner and CloudTrail; "
                    "remove unused grants "
                    "only after checking seasonal workloads and testing a narrower policy.",
                    service.namespace,
                )
            )
    return results


def stale_keys(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for principal in snapshot.principals:
        for key in principal.keys:
            if key.status != "Active":
                continue
            age = days_since(key.created_at, now)
            unused = days_since(key.last_used or key.created_at, now)
            reasons = []
            if unused >= config.thresholds.key_unused_days:
                reasons.append("no recent use")
            if age >= config.thresholds.key_rotation_days:
                reasons.append("rotation threshold reached")
            if not reasons:
                continue
            results.append(
                finding(
                    snapshot,
                    RuleId.STALE_KEYS,
                    Severity.HIGH if "no recent use" in reasons else Severity.MEDIUM,
                    principal.arn,
                    "Active access key needs review",
                    {
                        "key_fingerprint": key.fingerprint,
                        "key_suffix": key.suffix,
                        "age_days": age,
                        "unused_days": unused,
                        "reasons": reasons,
                        "last_used": key.last_used.isoformat() if key.last_used else None,
                    },
                    "Identify the key by suffix and fingerprint. "
                    "Migrate to temporary role credentials; "
                    "otherwise rotate with a tested overlap, deactivate, then delete the old key.",
                    key.fingerprint,
                )
            )
    return results


def latest_activity(principal: Principal) -> datetime:
    values = [principal.created_at]
    values.extend(
        value
        for value in [principal.password_last_used, principal.role_last_used]
        if value is not None
    )
    values.extend(key.last_used for key in principal.keys if key.last_used is not None)
    values.extend(
        service.last_authenticated
        for service in principal.services
        if service.last_authenticated is not None
    )
    return max(value.replace(tzinfo=value.tzinfo or UTC) for value in values)


def inactive_identities(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for principal in snapshot.principals:
        # Missing observations cannot establish inactivity.
        if not principal.advisor_complete or not principal.identity_complete:
            continue
        latest = latest_activity(principal)
        if days_since(latest, now) >= config.thresholds.inactive_days:
            results.append(
                finding(
                    snapshot,
                    RuleId.INACTIVE_IDENTITIES,
                    Severity.MEDIUM,
                    principal.arn,
                    f"{principal.kind.title()} has no recent recorded activity",
                    {
                        "latest_activity_or_creation": latest.isoformat(),
                        "inactive_days": days_since(latest, now),
                        "kind": principal.kind,
                    },
                    "Confirm ownership and seasonal use, remove unneeded permissions, and disable "
                    "unused credentials or retire the role through a reviewed change.",
                )
            )
    return results


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def statements(document: dict[str, Any]) -> Iterator[tuple[int, dict[str, Any]]]:
    rows = document.get("Statement", [])
    if isinstance(rows, dict):
        rows = [rows]
    if isinstance(rows, list):
        for index, row in enumerate(rows):
            if isinstance(row, dict) and row.get("Effect") == "Allow":
                yield index, row


def wildcard_policies(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for policy in snapshot.policies:
        for index, statement in statements(policy.document):
            action_star = "*" in strings(statement.get("Action"))
            resource_star = "*" in strings(statement.get("Resource"))
            if action_star or resource_star:
                results.append(
                    finding(
                        snapshot,
                        RuleId.WILDCARD_POLICIES,
                        Severity.HIGH if action_star else Severity.MEDIUM,
                        policy.resource,
                        "Allow statement contains a global wildcard",
                        {
                            "statement_index": index,
                            "source": policy.source,
                            "action_star": action_star,
                            "resource_star": resource_star,
                            "condition_present": bool(statement.get("Condition")),
                        },
                        "Replace global actions with required actions and scope resources where "
                        "supported. Document actions requiring Resource '*' with a suppression.",
                        str(index),
                    )
                )
    return results


def admin_access(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for principal in snapshot.principals:
        for arn in sorted(set(principal.attached_policy_arns)):
            if re.fullmatch(r"arn:[^:]+:iam::aws:policy/AdministratorAccess", arn):
                results.append(
                    finding(
                        snapshot,
                        RuleId.ADMIN_ACCESS,
                        Severity.CRITICAL,
                        principal.arn,
                        "AdministratorAccess is attached directly or through a group",
                        {"policy_name": "AdministratorAccess", "attachment": "direct or group"},
                        "Replace AdministratorAccess with a scoped role; restrict privileged "
                        "sessions with approval, MFA, and an appropriate permissions boundary.",
                        arn,
                    )
                )
    for policy in snapshot.policies:
        for index, statement in statements(policy.document):
            resources = strings(statement.get("Resource"))
            broad_resources = [
                resource
                for resource in resources
                if resource == "*"
                or (":iam::" in resource and ("*" in resource or "?" in resource))
            ]
            if not broad_resources:
                continue
            actions = [action.lower() for action in strings(statement.get("Action"))]
            all_iam = any(action in {"*", "iam:*"} for action in actions)
            pass_role = any(
                fnmatch.fnmatchcase("iam:passrole", action) for action in actions
            ) and any(resource == "*" or ":role/" in resource for resource in broad_resources)
            if not all_iam and not pass_role:
                continue
            results.append(
                finding(
                    snapshot,
                    RuleId.ADMIN_ACCESS,
                    Severity.CRITICAL
                    if all_iam and not statement.get("Condition")
                    else Severity.HIGH,
                    policy.resource,
                    "Broad IAM administration or PassRole grant",
                    {
                        "statement_index": index,
                        "all_iam_actions": all_iam,
                        "pass_role": pass_role,
                        "resources": resources,
                        "condition_present": bool(statement.get("Condition")),
                        "assessment": "escalation candidate, effective privilege not proven",
                    },
                    "Restrict IAM actions and role ARNs, require iam:PassedToService for PassRole, "
                    "and review boundaries, denies, and the caller's related service grants.",
                    str(index),
                )
            )
    return results


def missing_mfa(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    return [
        finding(
            snapshot,
            RuleId.MISSING_MFA,
            Severity.HIGH if principal.console_enabled else Severity.LOW,
            principal.arn,
            "IAM user has no assigned MFA device",
            {"console_enabled": principal.console_enabled, "mfa_device_assigned": False},
            "Assign and enforce MFA for interactive access; migrate programmatic-only users "
            "to workload roles. An assigned device alone does not prove policy enforcement.",
        )
        for principal in snapshot.principals
        if principal.kind == "user" and principal.identity_complete and not principal.mfa_enabled
    ]


def enforced_external_id(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for operator in ("StringEquals", "StringLike"):
        values = condition.get(operator, {})
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            identifiers = strings(value)
            if (
                key.lower() == "sts:externalid"
                and identifiers
                and all(
                    identifier.strip() and "*" not in identifier and "?" not in identifier
                    for identifier in identifiers
                )
            ):
                return True
    return False


def external_trust(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    trusted = {snapshot.account_id, *config.trusted_accounts}
    for principal in snapshot.principals:
        if principal.kind != "role":
            continue
        for index, statement in statements(principal.trust):
            if not any(
                fnmatch.fnmatchcase("sts:assumerole", action.lower())
                for action in strings(statement.get("Action"))
            ):
                continue
            raw = statement.get("Principal", {})
            aws_principals = strings(raw.get("AWS")) if isinstance(raw, dict) else strings(raw)
            external = []
            for value in aws_principals:
                match = re.fullmatch(r"arn:[^:]+:iam::(\d{12}):.+", value)
                account = match.group(1) if match else value
                if account == "*" or account not in trusted:
                    external.append(value)
            if not external:
                continue
            guarded = enforced_external_id(statement.get("Condition"))
            severity = Severity.LOW if guarded else Severity.HIGH
            if "*" in external:
                severity = Severity.HIGH if guarded else Severity.CRITICAL
            results.append(
                finding(
                    snapshot,
                    RuleId.EXTERNAL_TRUST,
                    severity,
                    principal.arn,
                    "Role trusts an external AWS principal",
                    {
                        "statement_index": index,
                        "external_principals": external,
                        "external_id_enforced": guarded,
                        "other_conditions_present": bool(statement.get("Condition")),
                    },
                    "Restrict trust to approved role ARNs. For delegated third-party "
                    "access require a unique ExternalId with StringEquals; review other conditions "
                    "and keep a trusted-account exception only with an owner and reason.",
                    str(index),
                )
            )
    return results


def federated_trust(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = []
    for principal in snapshot.principals:
        for index, statement in statements(principal.trust):
            raw = statement.get("Principal", {})
            providers = strings(raw.get("Federated")) if isinstance(raw, dict) else []
            actions = [a.lower() for a in strings(statement.get("Action"))]
            if not providers or not any(
                fnmatch.fnmatchcase("sts:assumerolewithwebidentity", a) for a in actions
            ):
                continue
            for provider in providers:
                if ":oidc-provider/" not in provider:
                    continue
                issuer = provider.split(":oidc-provider/", 1)[1]
                conditions = statement.get("Condition", {})
                constrained = []
                for claim in ("aud", "sub"):
                    values = (
                        conditions.get("StringEquals", {}) if isinstance(conditions, dict) else {}
                    )
                    matches = (
                        strings(values.get(f"{issuer}:{claim}")) if isinstance(values, dict) else []
                    )
                    if matches and all(
                        v.strip() and "*" not in v and "?" not in v for v in matches
                    ):
                        constrained.append(claim)
                if len(constrained) == 2:
                    continue
                results.append(
                    finding(
                        snapshot,
                        RuleId.FEDERATED_TRUST,
                        Severity.HIGH,
                        principal.arn,
                        "OIDC trust lacks exact audience or subject constraints",
                        {
                            "statement_index": index,
                            "provider": provider,
                            "exact_claims": constrained,
                            "condition_present": bool(conditions),
                        },
                        "Review issuer-specific claims; restrict audience and subjects to approved "
                        "workloads. Pattern-based conditions may be intentional "
                        "and require review.",
                        f"{index}:{provider}",
                    )
                )
    return results


def analyzer_evidence(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    return [
        finding(
            snapshot,
            RuleId.ANALYZER,
            Severity.HIGH,
            str(row["resource"]),
            "Access Analyzer reports active external access",
            row,
            "Review the analyzer trust zone, finding timestamp and resource policy; "
            "confirm intended sharing before changing access.",
            str(row["id"]),
        )
        for row in snapshot.analyzer_findings
    ]


RULES: tuple[Callable[[Snapshot, Config, datetime], list[Finding]], ...] = (
    unused_permissions,
    stale_keys,
    inactive_identities,
    wildcard_policies,
    admin_access,
    missing_mfa,
    external_trust,
    federated_trust,
    analyzer_evidence,
)


def evaluate(snapshot: Snapshot, config: Config, now: datetime) -> list[Finding]:
    results = [result for rule in RULES for result in rule(snapshot, config, now)]
    boundaries = {p.arn: p.permissions_boundary for p in snapshot.principals}
    for result in results:
        owner = result.resource.split("#inline/", 1)[0]
        if boundaries.get(owner):
            result.evidence["permissions_boundary"] = boundaries[owner]
            result.evidence["boundary_effect"] = "not evaluated"
    return results
