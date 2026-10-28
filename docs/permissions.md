# Read-only permission mapping

The target role uses [auditor-read-only.json](../policy/auditor-read-only.json). Its Resource wildcard supports inventory across the account; the action list is explicit and contains no IAM mutation permissions.

| API permission | Why it is needed |
| --- | --- |
| iam:GetAccountAuthorizationDetails | Paginated users, roles, groups, inline policies, local managed policy versions, attachment relationships, and role last-use metadata. |
| iam:GetUser | PasswordLastUsed, which is absent from the account authorization inventory. |
| iam:GetLoginProfile | Distinguish console-enabled users; NoSuchEntity is an expected absence. Other failures are incomplete collection. |
| iam:ListMFADevices | Assigned hardware or virtual MFA devices per user. |
| iam:ListAccessKeys | Key status and creation date, with pagination. |
| iam:GetAccessKeyLastUsed | Last recorded use per key. Secret keys cannot be retrieved by these APIs. |
| iam:GenerateServiceLastAccessedDetails | Request service-level observation reports per user and role. Does not modify IAM authorization or credentials. |
| iam:GetServiceLastAccessedDetails | Bounded polling and pagination of those reports in the session that generated them. |

For assume-role collection, the source identity needs `sts:AssumeRole` only for the specific target role ARNs in [the caller example](../policy/assume-audit-role.example.json). The target trust policy must permit that exact source principal; [the trust example](../policy/target-role-trust.example.json) also requires a fictional ExternalId. ExternalId is not a password and must not replace a narrow Principal. Configure real values privately; none are shipped here.

The tool requests one-hour temporary sessions and supplies the session token only to the in-memory Boto3 session. It does not save or log assumed credentials. The target role should have no permission to modify IAM. Existing profiles should use temporary authentication; the tool never creates a role, key, trust relationship, or policy in live mode.

`sts:GetCallerIdentity` is used only when auditing the current account. AWS does not require an explicit permission grant for that API. No Organizations, CloudTrail, S3, or permission-simulation permissions are needed.

References:

- [Boto3 GetAccountAuthorizationDetails](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_authorization_details.html)
- [Boto3 GenerateServiceLastAccessedDetails](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/generate_service_last_accessed_details.html)
- [AWS last-accessed information and tracking limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html)
- [AWS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [AWS ExternalId guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
- [Moto IAM support](https://docs.getmoto.org/en/latest/docs/services/iam.html)
