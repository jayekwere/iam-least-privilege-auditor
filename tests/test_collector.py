import json
import os
from typing import Any
from unittest.mock import Mock, patch
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber
from moto import mock_aws

from iam_auditor.collector import Collector, collect_accounts, policy_document
from iam_auditor.demo import (
    DEMO_ACCOUNT,
    DEMO_NOW,
    EXTERNAL_ACCOUNT,
    mock_inventory,
    queue_advisor,
    trust,
)
from iam_auditor.models import Principal, Snapshot


def iam_client() -> Any:
    return boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="mock-access-key",
        aws_secret_access_key="mock-secret-not-valid",
    )


def test_decode_document() -> None:
    document = {"Version": "2012-10-17", "Statement": []}
    assert policy_document(quote(json.dumps(document))) == document
    with pytest.raises(ValueError, match="object"):
        policy_document("[]")


def test_inventory_pagination_and_bad_markers() -> None:
    client = iam_client()
    expected = {"Filter": ["User", "Role", "Group", "LocalManagedPolicy"]}
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_account_authorization_details",
            {
                "IsTruncated": True,
                "Marker": "mock-page-2",
            },
            expected,
        )
        stubber.add_response(
            "get_account_authorization_details",
            {"IsTruncated": False},
            {
                **expected,
                "Marker": "mock-page-2",
            },
        )
        assert not Collector(client, DEMO_ACCOUNT).collect().issues
        stubber.assert_no_pending_responses()
    for marker in [None, "repeated"]:
        collector = Collector(Mock(), DEMO_ACCOUNT)
        page: dict[str, Any] = {"IsTruncated": True}
        if marker:
            page["Marker"] = marker
        collector.iam.get_account_authorization_details.return_value = page
        assert collector.collect().issues[0].code == "InvalidPaginationMarker"


def test_inventory_access_denied_and_sdk_errors() -> None:
    client = iam_client()
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "get_account_authorization_details", service_error_code="AccessDenied"
        )
        snapshot = Collector(client, DEMO_ACCOUNT).collect()
        assert snapshot.issues[0].code == "AccessDenied"
        assert not snapshot.principals
    for error in [
        EndpointConnectionError(endpoint_url="https://mock.invalid"),
        NotImplementedError(),
    ]:
        client = Mock()
        client.get_user.side_effect = error
        collector = Collector(client, DEMO_ACCOUNT)
        assert collector.call(client, "get_user", "mock-user") is None
        assert collector.snapshot.issues[0].code == type(error).__name__


def test_missing_default_policy_version_is_incomplete() -> None:
    client = Mock()
    client.get_account_authorization_details.return_value = {
        "Policies": [
            {
                "Arn": f"arn:aws:iam::{DEMO_ACCOUNT}:policy/mock",
                "PolicyVersionList": [],
            }
        ]
    }
    assert Collector(client, DEMO_ACCOUNT).collect().issues[0].code == "MissingDefaultVersion"


def test_advisor_pending_and_pagination(snapshot: Snapshot) -> None:
    principal = snapshot.principals[0]
    principal.services = []
    principal.advisor_complete = False
    client = iam_client()
    with Stubber(client) as stubber:
        queue_advisor(stubber, principal.arn, [], pending=True)
        sleep = Mock()
        collector = Collector(client, DEMO_ACCOUNT, sleep=sleep)
        collector.service_access(principal)
        assert principal.advisor_complete
        sleep.assert_called_once_with(1.0)
    job = str(uuid5(NAMESPACE_URL, principal.arn))
    base = {"JobStatus": "COMPLETED", "JobCreationDate": DEMO_NOW, "JobCompletionDate": DEMO_NOW}
    with Stubber(client) as stubber:
        stubber.add_response("generate_service_last_accessed_details", {"JobId": job})
        stubber.add_response(
            "get_service_last_accessed_details",
            {
                **base,
                "IsTruncated": True,
                "Marker": "page2",
                "ServicesLastAccessed": [
                    {"ServiceName": "S3", "ServiceNamespace": "s3", "TotalAuthenticatedEntities": 0}
                ],
            },
            {"JobId": job},
        )
        stubber.add_response(
            "get_service_last_accessed_details",
            {
                **base,
                "IsTruncated": False,
                "ServicesLastAccessed": [],
            },
            {"JobId": job, "Marker": "page2"},
        )
        Collector(client, DEMO_ACCOUNT).service_access(principal)
        assert principal.advisor_complete and principal.services[0].namespace == "s3"
        stubber.assert_no_pending_responses()


@pytest.mark.parametrize(
    "case, code",
    [
        ("generate_denied", "AccessDenied"),
        ("get_denied", "AccessDenied"),
        ("failed", "AdvisorJobFailed"),
        ("pending", "AdvisorPollTimeout"),
        ("bad_marker", "InvalidPaginationMarker"),
        ("repeated_marker", "InvalidPaginationMarker"),
        ("page_denied", "AccessDenied"),
        ("page_failed", "AdvisorJobFailed"),
    ],
)
def test_advisor_failures_do_not_claim_complete(snapshot: Snapshot, case: str, code: str) -> None:
    principal = snapshot.principals[0]
    principal.advisor_complete = False
    client = Mock()
    client.generate_service_last_accessed_details.return_value = {"JobId": "mock-job"}
    client.get_service_last_accessed_details.return_value = {"JobStatus": "COMPLETED"}
    denied = ClientError({"Error": {"Code": "AccessDenied"}}, "MockOperation")
    if case == "generate_denied":
        client.generate_service_last_accessed_details.side_effect = denied
    elif case == "get_denied":
        client.get_service_last_accessed_details.side_effect = denied
    elif case == "failed":
        client.get_service_last_accessed_details.return_value = {"JobStatus": "FAILED"}
    elif case == "pending":
        client.get_service_last_accessed_details.return_value = {"JobStatus": "IN_PROGRESS"}
    else:
        first: dict[str, Any] = {"JobStatus": "COMPLETED", "IsTruncated": True}
        if case != "bad_marker":
            first["Marker"] = "mock-marker"
        if case == "page_denied":
            client.get_service_last_accessed_details.side_effect = [first, denied]
        elif case == "page_failed":
            client.get_service_last_accessed_details.side_effect = [first, {"JobStatus": "FAILED"}]
        else:
            client.get_service_last_accessed_details.return_value = first
    collector = Collector(client, DEMO_ACCOUNT, poll_attempts=1)
    collector.service_access(principal)
    assert not principal.advisor_complete and collector.snapshot.issues[0].code == code


def test_missing_user_key_observations_never_become_unused_claims(snapshot: Snapshot) -> None:
    principal = snapshot.principals[0]
    principal.keys = []
    client = Mock()
    client.get_user.return_value = {"User": {}}
    client.get_login_profile.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "Get")
    client.list_mfa_devices.return_value = {"MFADevices": []}
    client.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "MOCK-ACCESS-KEY-DEMO-0000",
                "Status": "Active",
                "CreateDate": DEMO_NOW,
            }
        ]
    }
    client.get_access_key_last_used.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "Get"
    )
    collector = Collector(client, DEMO_ACCOUNT)
    collector.user_details(principal)
    assert not principal.identity_complete and not principal.keys


def test_assume_role_multiple_accounts_external_id_and_failure() -> None:
    session = Mock()
    session.region_name = "us-east-1"
    sts = session.client.return_value
    sts.assume_role.side_effect = [
        {"Credentials": {"AccessKeyId": "mock", "SecretAccessKey": "mock", "SessionToken": "mock"}},
        ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole"),
    ]
    with (
        patch("iam_auditor.collector.boto3.Session") as assumed,
        patch.object(Collector, "collect", return_value=Snapshot(account_id=DEMO_ACCOUNT)),
    ):
        results = collect_accounts(
            session,
            [DEMO_ACCOUNT, "111111111111", DEMO_ACCOUNT],
            "mock/AuditRole",
            "mock-external-id",
            "aws-us-gov",
        )
    assert len(results) == 2 and results[1].issues[0].operation == "assume_role"
    first = sts.assume_role.call_args_list[0].kwargs
    assert first["RoleArn"] == f"arn:aws-us-gov:iam::{DEMO_ACCOUNT}:role/mock/AuditRole"
    assert first["ExternalId"] == "mock-external-id"
    assert first["DurationSeconds"] == 3600
    assert assumed.call_args.kwargs["aws_session_token"] == "mock"


def test_current_account_session_with_moto() -> None:
    with mock_inventory():
        session = boto3.Session(
            aws_access_key_id="mock-access-key",
            aws_secret_access_key="mock-secret-not-valid",
            region_name="us-east-1",
        )
        with patch.object(Collector, "collect", return_value=Snapshot(account_id=DEMO_ACCOUNT)):
            assert collect_accounts(session, [], None)[0].account_id == DEMO_ACCOUNT


def test_real_sdk_assume_role_keeps_two_moto_accounts_isolated() -> None:
    def observed(self: Collector, principal: Principal) -> None:
        # Access Advisor is deliberately synthetic; STS and inventory use the real SDK with Moto.
        principal.advisor_complete = True

    with patch.dict(os.environ), mock_aws():
        os.environ.pop("MOTO_ACCOUNT_ID", None)
        base = boto3.Session(
            aws_access_key_id="mock-access-key",
            aws_secret_access_key="mock-secret-not-valid",
            region_name="us-east-1",
        )
        sessions: dict[str, Any] = {}
        for account in [DEMO_ACCOUNT, EXTERNAL_ACCOUNT]:
            credentials = base.client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/MockAudit",
                RoleSessionName="mock-seed",
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name="us-east-1",
            )
            iam = session.client("iam")
            iam.create_role(
                RoleName="MockAudit", AssumeRolePolicyDocument=json.dumps(trust(DEMO_ACCOUNT))
            )
            iam.create_user(UserName="mock-account-user")
            sessions[account] = session
        with patch.object(Collector, "service_access", observed):
            snapshots = collect_accounts(
                sessions[DEMO_ACCOUNT],
                [DEMO_ACCOUNT, EXTERNAL_ACCOUNT],
                "MockAudit",
            )
        assert [item.account_id for item in snapshots] == [DEMO_ACCOUNT, EXTERNAL_ACCOUNT]
        for snapshot in snapshots:
            assert not snapshot.issues and len(snapshot.principals) == 2
            assert all(
                f"::{snapshot.account_id}:" in principal.arn for principal in snapshot.principals
            )
