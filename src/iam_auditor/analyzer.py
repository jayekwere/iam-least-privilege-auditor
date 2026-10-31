"""Optional regional external Access Analyzer evidence; never creates analyzers."""

from typing import Any

from iam_auditor.collector import Collector
from iam_auditor.models import Snapshot


def collect_analyzer(client: Any, snapshot: Snapshot, arn: str, max_pages: int = 1000) -> None:
    collector = Collector(client, snapshot.account_id, max_pages=max_pages)
    collector.snapshot = snapshot
    token: str | None = None
    seen: set[str] = set()
    for _ in range(max_pages):
        request: dict[str, Any] = {
            "analyzerArn": arn,
            "filter": {"status": {"eq": ["ACTIVE"]}},
            "maxResults": 100,
        }
        if token:
            request["nextToken"] = token
        page = collector.call(client, "list_findings", arn, **request)
        if page is None:
            return
        for row in page.get("findings", []):
            if row.get("resourceType") == "AWS::IAM::Role":
                snapshot.analyzer_findings.append(
                    {
                        "id": row["id"],
                        "resource": row["resource"],
                        "analyzer": arn,
                        "is_public": row.get("isPublic", False),
                        "updated_at": row["updatedAt"].isoformat(),
                        "assessment": "AWS external-access evidence; effective sessions not proven",
                    }
                )
        token = page.get("nextToken")
        if not token:
            return
        if token in seen:
            collector.issue(arn, "list_findings", "InvalidPaginationMarker")
            return
        seen.add(token)
    collector.issue(arn, "list_findings", "PaginationLimitExceeded")
