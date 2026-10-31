"""Read-only IAM inventory and bounded Access Advisor polling.

Any dynamically typed AWS response is normalized before it reaches a rule.
"""

import hashlib
import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from iam_auditor.models import (
    AccessKey,
    CollectionIssue,
    Policy,
    Principal,
    ServiceAccess,
    Snapshot,
)

SDK_CONFIG = BotoConfig(
    connect_timeout=5,
    read_timeout=20,
    retries={"max_attempts": 3, "mode": "standard"},
)


def policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(unquote(value))
    if not isinstance(value, dict):
        raise ValueError("Policy document must be an object")
    return value


class Collector:
    def __init__(
        self,
        iam: Any,
        account_id: str,
        advisor: Any = None,
        poll_attempts: int = 30,
        poll_interval: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        max_pages: int = 1000,
    ) -> None:
        if not 1 <= max_pages <= 10000:
            raise ValueError("max_pages must be between 1 and 10000")
        if not 1 <= poll_attempts <= 300 or not 0 <= poll_interval <= 60:
            raise ValueError("Invalid polling bounds")
        self.max_pages = max_pages
        self.iam = iam
        self.advisor = advisor if advisor is not None else iam
        self.snapshot = Snapshot(account_id=account_id)
        self.poll_attempts = poll_attempts
        self.poll_interval = poll_interval
        self.sleep = sleep

    def issue(self, resource: str, operation: str, code: str) -> None:
        self.snapshot.issues.append(
            CollectionIssue(
                account_id=self.snapshot.account_id,
                resource=resource,
                operation=operation,
                code=code,
            )
        )

    def call(
        self,
        client: Any,
        operation: str,
        resource: str,
        missing_ok: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        try:
            response: dict[str, Any] = getattr(client, operation)(**kwargs)
            return response
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code", "ClientError"))
            if not (missing_ok and code == "NoSuchEntity"):
                self.issue(resource, operation, code)
        except (BotoCoreError, NotImplementedError) as error:
            self.issue(resource, operation, type(error).__name__)
        return None

    def pages(self, operation: str, resource: str, **kwargs: Any) -> list[dict[str, Any]]:
        pages = []
        seen = set()
        while True:
            page = self.call(self.iam, operation, resource, **kwargs)
            if page is None:
                break
            pages.append(page)
            if page.get("IsTruncated") and len(pages) >= self.max_pages:
                self.issue(resource, operation, "PaginationLimitExceeded")
                break
            if not page.get("IsTruncated"):
                break
            marker = page.get("Marker")
            if not marker or marker in seen:
                self.issue(resource, operation, "InvalidPaginationMarker")
                break
            seen.add(marker)
            kwargs["Marker"] = marker
        return pages

    def service_access(self, principal: Principal) -> None:
        job = self.call(
            self.advisor,
            "generate_service_last_accessed_details",
            principal.arn,
            Arn=principal.arn,
            Granularity="SERVICE_LEVEL",
        )
        if job is None:
            return
        job_id = job["JobId"]
        for attempt in range(self.poll_attempts):
            page = self.call(
                self.advisor,
                "get_service_last_accessed_details",
                principal.arn,
                JobId=job_id,
            )
            if page is None:
                return
            status = page.get("JobStatus")
            if status == "COMPLETED":
                break
            if status != "IN_PROGRESS":
                self.issue(principal.arn, "get_service_last_accessed_details", "AdvisorJobFailed")
                return
            if attempt + 1 < self.poll_attempts:
                self.sleep(self.poll_interval)
        else:
            self.issue(principal.arn, "get_service_last_accessed_details", "AdvisorPollTimeout")
            return
        seen = set()
        page_count = 0
        while True:
            page_count += 1
            principal.services.extend(
                ServiceAccess(
                    namespace=service["ServiceNamespace"],
                    last_authenticated=service.get("LastAuthenticated"),
                )
                for service in page.get("ServicesLastAccessed", [])
            )
            if not page.get("IsTruncated"):
                principal.advisor_complete = True
                return
            if page_count >= self.max_pages:
                self.issue(
                    principal.arn, "get_service_last_accessed_details", "PaginationLimitExceeded"
                )
                return
            marker = page.get("Marker")
            if not marker or marker in seen:
                self.issue(
                    principal.arn, "get_service_last_accessed_details", "InvalidPaginationMarker"
                )
                return
            seen.add(marker)
            next_page = self.call(
                self.advisor,
                "get_service_last_accessed_details",
                principal.arn,
                JobId=job_id,
                Marker=marker,
            )
            if next_page is None:
                return
            if next_page.get("JobStatus") != "COMPLETED":
                self.issue(principal.arn, "get_service_last_accessed_details", "AdvisorJobFailed")
                return
            page = next_page

    def user_details(self, principal: Principal) -> None:
        before = len(self.snapshot.issues)
        user = self.call(self.iam, "get_user", principal.arn, UserName=principal.name)
        if user:
            principal.password_last_used = user["User"].get("PasswordLastUsed")
        login = self.call(
            self.iam,
            "get_login_profile",
            principal.arn,
            missing_ok=True,
            UserName=principal.name,
        )
        principal.console_enabled = login is not None
        devices = self.pages("list_mfa_devices", principal.arn, UserName=principal.name)
        principal.mfa_enabled = any(page.get("MFADevices") for page in devices)
        for page in self.pages("list_access_keys", principal.arn, UserName=principal.name):
            for key in page.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                last = self.call(
                    self.iam,
                    "get_access_key_last_used",
                    principal.arn,
                    AccessKeyId=key_id,
                )
                if last is None:
                    continue
                # Only an identifier suffix and one-way fingerprint enter a report.
                principal.keys.append(
                    AccessKey(
                        fingerprint=hashlib.sha256(key_id.encode()).hexdigest()[:16],
                        suffix=key_id[-4:],
                        status=key["Status"],
                        created_at=key["CreateDate"],
                        last_used=last.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if last
                        else None,
                    )
                )
        principal.identity_complete = len(self.snapshot.issues) == before

    def add_inline(self, resource: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            self.snapshot.policies.append(
                Policy(
                    resource=f"{resource}#inline/{row['PolicyName']}",
                    document=policy_document(row["PolicyDocument"]),
                    source="inline",
                )
            )

    def collect(self) -> Snapshot:
        inventory = self.pages(
            "get_account_authorization_details",
            self.snapshot.account_id,
            Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"],
        )
        groups: dict[str, list[str]] = {}
        for page in inventory:
            for group in page.get("GroupDetailList", []):
                groups[group["GroupName"]] = [
                    policy["PolicyArn"] for policy in group.get("AttachedManagedPolicies", [])
                ]
                self.add_inline(group["Arn"], group.get("GroupPolicyList", []))
            for policy in page.get("Policies", []):
                if ":iam::aws:policy/" in policy["Arn"] and not policy.get("AttachmentCount"):
                    continue
                versions = [
                    version
                    for version in policy.get("PolicyVersionList", [])
                    if version.get("IsDefaultVersion")
                ]
                if not versions:
                    self.issue(
                        policy["Arn"], "get_account_authorization_details", "MissingDefaultVersion"
                    )
                for version in versions:
                    self.snapshot.policies.append(
                        Policy(
                            resource=policy["Arn"],
                            document=policy_document(version["Document"]),
                            source="aws-managed"
                            if ":iam::aws:policy/" in policy["Arn"]
                            else "customer-managed",
                        )
                    )
        for page in inventory:
            for field, kind, name_key, inline_key in [
                ("UserDetailList", "user", "UserName", "UserPolicyList"),
                ("RoleDetailList", "role", "RoleName", "RolePolicyList"),
            ]:
                for raw in page.get(field, []):
                    principal = Principal(
                        arn=raw["Arn"],
                        name=raw[name_key],
                        kind="user" if kind == "user" else "role",
                        created_at=raw["CreateDate"],
                        role_last_used=raw.get("RoleLastUsed", {}).get("LastUsedDate"),
                        attached_policy_arns=[
                            policy["PolicyArn"] for policy in raw.get("AttachedManagedPolicies", [])
                        ],
                        permissions_boundary=raw.get("PermissionsBoundary", {}).get(
                            "PermissionsBoundaryArn"
                        ),
                        trust=policy_document(raw.get("AssumeRolePolicyDocument", {})),
                    )
                    for group in raw.get("GroupList", []):
                        principal.attached_policy_arns.extend(groups.get(group, []))
                    self.add_inline(principal.arn, raw.get(inline_key, []))
                    if kind == "user":
                        self.user_details(principal)
                    self.service_access(principal)
                    self.snapshot.principals.append(principal)
        return self.snapshot


def collect_accounts(
    session: Any,
    accounts: list[str],
    role_name: str | None,
    external_id: str | None = None,
    partition: str = "aws",
) -> list[Snapshot]:
    snapshots = []
    if not accounts:
        account = session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"]
        return [Collector(session.client("iam", config=SDK_CONFIG), account).collect()]
    for account in dict.fromkeys(accounts):
        try:
            request = {
                "RoleArn": f"arn:{partition}:iam::{account}:role/{role_name}",
                "RoleSessionName": "iam-least-privilege-audit",
                "DurationSeconds": 3600,
            }
            if external_id:
                request["ExternalId"] = external_id
            assumed = session.client("sts", config=SDK_CONFIG).assume_role(**request)["Credentials"]
            target = boto3.Session(
                aws_access_key_id=assumed["AccessKeyId"],
                aws_secret_access_key=assumed["SecretAccessKey"],
                aws_session_token=assumed["SessionToken"],
                region_name=session.region_name,
            )
            iam = target.client("iam", config=SDK_CONFIG)
            snapshots.append(Collector(iam, account).collect())
        except (ClientError, BotoCoreError) as error:
            code = (
                str(error.response.get("Error", {}).get("Code", "ClientError"))
                if isinstance(error, ClientError)
                else type(error).__name__
            )
            snapshots.append(
                Snapshot(
                    account_id=account,
                    issues=[
                        CollectionIssue(
                            account_id=account,
                            resource=account,
                            operation="assume_role",
                            code=code,
                        )
                    ],
                )
            )
    return snapshots
