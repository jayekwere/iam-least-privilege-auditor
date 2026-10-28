"""Disposable fictional IAM inventory. Never opens a real AWS session.

Moto does not implement Access Advisor. Botocore Stubber supplies explicit,
documented service-last-accessed observations; all inventory comes from Moto.
"""

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

import boto3
from botocore.stub import Stubber

from iam_auditor.collector import Collector
from iam_auditor.models import Snapshot

DEMO_NOW = datetime(2026, 1, 15, 12, tzinfo=UTC)
DEMO_ACCOUNT = "000000000000"
EXTERNAL_ACCOUNT = "111111111111"
MOCK_KEY_ID = "MOCK-ACCESS-KEY-DEMO-0000"


def allow(actions: str | list[str], resource: str = "*") -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resource},
        ],
    }


def trust(account: str, external_id: bool = False) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }
    if external_id:
        statement["Condition"] = {"StringEquals": {"sts:ExternalId": "mock-delegation-id"}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def seed_environment(iam: Any, now: datetime = DEMO_NOW) -> None:
    """Create deliberately overprivileged, fictional objects inside an active Moto context."""
    with patch("moto.iam.models.utcnow", return_value=now - timedelta(days=180)):
        iam.create_user(UserName="mock-alder")
        iam.create_user(UserName="mock-birch")
        # The password and key are fake, stay in Moto memory, and cannot authenticate to AWS.
        iam.create_login_profile(
            UserName="mock-alder", Password="MOCK-ONLY-not-a-real-password-42!"
        )
        with patch(
            "moto.iam.models.generate_access_key_id_from_account_id", return_value=MOCK_KEY_ID
        ):
            iam.create_access_key(UserName="mock-alder")
        iam.create_group(GroupName="mock-maintainers")
        iam.add_user_to_group(GroupName="mock-maintainers", UserName="mock-alder")
        iam.attach_group_policy(
            GroupName="mock-maintainers",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        iam.create_policy(PolicyName="mock-global", PolicyDocument=json.dumps(allow("*")))
        iam.create_policy(
            PolicyName="mock-pass-role",
            PolicyDocument=json.dumps(allow("iam:PassRole", f"arn:aws:iam::{DEMO_ACCOUNT}:role/*")),
        )
        iam.put_group_policy(
            GroupName="mock-maintainers",
            PolicyName="mock-service-list",
            PolicyDocument=json.dumps(allow("ec2:DescribeInstances")),
        )
        iam.put_user_policy(
            UserName="mock-alder",
            PolicyName="mock-unused-service",
            PolicyDocument=json.dumps(allow("s3:ListAllMyBuckets")),
        )
        iam.create_role(
            RoleName="mock-external-unguarded",
            AssumeRolePolicyDocument=json.dumps(trust(EXTERNAL_ACCOUNT)),
        )
        iam.create_role(
            RoleName="mock-external-guarded",
            AssumeRolePolicyDocument=json.dumps(trust(EXTERNAL_ACCOUNT, external_id=True)),
        )
        iam.put_role_policy(
            RoleName="mock-external-unguarded",
            PolicyName="mock-iam-admin",
            PolicyDocument=json.dumps(allow("iam:*")),
        )
    with patch("moto.iam.models.utcnow", return_value=now - timedelta(days=2)):
        iam.create_user(UserName="mock-recent-mfa")
        iam.enable_mfa_device(
            UserName="mock-recent-mfa",
            SerialNumber=f"arn:aws:iam::{DEMO_ACCOUNT}:mfa/mock-device",
            AuthenticationCode1="000000",
            AuthenticationCode2="000000",
        )


@contextmanager
def mock_inventory(now: datetime = DEMO_NOW) -> Iterator[Any]:
    """An explicit fake credential session, independent of profiles or local AWS credentials."""
    from moto import mock_aws

    with (
        patch.dict(os.environ, {"MOTO_ACCOUNT_ID": DEMO_ACCOUNT}),
        mock_aws(config={"iam": {"load_aws_managed_policies": True}}),
    ):
        iam = boto3.client(
            "iam",
            region_name="us-east-1",
            aws_access_key_id="mock-access-key",
            aws_secret_access_key="mock-secret-not-valid",
        )
        seed_environment(iam, now)
        yield iam


def queue_advisor(
    stubber: Stubber,
    arn: str,
    services: list[dict[str, Any]],
    *,
    pending: bool = False,
) -> None:
    job = str(uuid5(NAMESPACE_URL, arn))
    stubber.add_response(
        "generate_service_last_accessed_details",
        {"JobId": job},
        {"Arn": arn, "Granularity": "SERVICE_LEVEL"},
    )
    if pending:
        stubber.add_response(
            "get_service_last_accessed_details",
            {
                "JobStatus": "IN_PROGRESS",
                "ServicesLastAccessed": [],
                "JobCreationDate": DEMO_NOW,
                "JobCompletionDate": DEMO_NOW,
            },
            {"JobId": job},
        )
    stubber.add_response(
        "get_service_last_accessed_details",
        {
            "JobStatus": "COMPLETED",
            "JobCreationDate": DEMO_NOW,
            "JobCompletionDate": DEMO_NOW,
            "ServicesLastAccessed": services,
            "IsTruncated": False,
        },
        {"JobId": job},
    )


def demo_snapshot(now: datetime = DEMO_NOW) -> Snapshot:
    with mock_inventory(now) as iam:
        advisor = boto3.client(
            "iam",
            region_name="us-east-1",
            aws_access_key_id="mock-access-key",
            aws_secret_access_key="mock-secret-not-valid",
        )
        inventory = iam.get_account_authorization_details(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"],
        )
        with Stubber(advisor) as stubber:
            for raw in [*inventory["UserDetailList"], *inventory["RoleDetailList"]]:
                services: list[dict[str, Any]] = []
                if raw.get("UserName") == "mock-alder":
                    services = [
                        {
                            "ServiceName": "Amazon S3",
                            "ServiceNamespace": "s3",
                            "LastAuthenticated": now - timedelta(days=120),
                            "TotalAuthenticatedEntities": 1,
                        }
                    ]
                if raw.get("RoleName") == "mock-external-guarded":
                    services = [
                        {
                            "ServiceName": "Amazon EC2",
                            "ServiceNamespace": "ec2",
                            "LastAuthenticated": now - timedelta(days=1),
                            "TotalAuthenticatedEntities": 1,
                        }
                    ]
                queue_advisor(stubber, raw["Arn"], services)
            snapshot = Collector(iam, DEMO_ACCOUNT, advisor=advisor, poll_interval=0).collect()
            stubber.assert_no_pending_responses()
            return snapshot
