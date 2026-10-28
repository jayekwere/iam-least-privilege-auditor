# iam-least-privilege-auditor

[![CI](https://github.com/jayekwere/iam-least-privilege-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/jayekwere/iam-least-privilege-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A personal, open-source Python CLI that reviews AWS IAM permissions, credentials, and role trust across explicit accounts. Least privilege reduces the damage an exposed credential or overpowered identity can cause. The auditor collects read-only observations and prioritizes review candidates with evidence and concrete remediation. It produces terminal, JSON, and Markdown reports, with a versioned JSON contract for a separate dashboard.

## Quickstart: no AWS account required

Requires Python 3.11 or later and Make. The first run downloads Python dependencies; subsequent demo runs need no network, credentials, or AWS account.

```sh
git clone https://github.com/jayekwere/iam-least-privilege-auditor.git
cd iam-least-privilege-auditor
make demo
```

If your system names the interpreter `python3.11`, run `make demo PYTHON=python3.11`. On systems without Make:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[demo]"
.venv/bin/iam-audit demo
```

Export any format or try a documented suppression:

```sh
.venv/bin/iam-audit demo --format json --output reports/demo.json
.venv/bin/iam-audit demo --format markdown --output reports/demo.md
.venv/bin/iam-audit demo --config examples/config.yaml
```

The demo uses Moto for IAM inventory and Botocore Stubber for Access Advisor, which Moto does not implement. Its clock is fixed at **2026-01-15T12:00:00Z**, with fictional users, accounts, policy documents, and historical observations. No real account is audited. The seeded policies are intentionally overprivileged examples, not deployment recommendations.

### Example demo result

The default demo produces **17 active findings: 3 critical, 5 high, 7 medium, and 2 low**. These are findings, not a count of distinct identities; several checks can flag the same resource.

| Severity | Rule | Resource, abbreviated | Observed evidence |
| --- | --- | --- | --- |
| critical | IAM005 | user/mock-alder | AdministratorAccess inherited through a group |
| high | IAM002 | user/mock-alder | Active key, 180 days old, no recorded use |
| high | IAM007 | role/mock-external-unguarded | External account trust without mandatory ExternalId |
| medium | IAM001 | user/mock-alder | S3 access attempt last recorded 120 days ago |
| low | IAM007 | role/mock-external-guarded | External trust with a mandatory, specific ExternalId |

Complete, generated examples: [JSON](examples/demo-report.json), [Markdown](examples/demo-report.md), and [terminal output](examples/demo-report.txt). All account-owned identifiers are fictional. AWS's shared AdministratorAccess policy is identified by its standard public policy name.

## Real AWS usage

Install only the runtime if the demo is not needed: `python -m pip install .`. Use your normal Boto3 credential chain, such as an authenticated SSO profile or an existing short-lived role session. Never place keys in the config file or source tree.

```sh
# Audit the account associated with an existing profile.
iam-audit audit --profile audit --format table

# Explicit, fictional account IDs. Replace locally with authorized targets.
iam-audit audit --profile audit \
  --account 000000000000 --account 111111111111 \
  --role-name LeastPrivilegeAudit --external-id mock-delegation-id \
  --format json --output reports/accounts.json

# A reviewed role path is supported, for example security/LeastPrivilegeAudit.
iam-audit audit --profile audit --config local-config.yaml \
  --format markdown --output reports/review.md
```

`--account` is repeatable and requires `--role-name`. The tool assumes that role independently in each listed account; one failed assumption does not stop the remaining accounts. `--region` defaults to `us-east-1`; use the appropriate regional endpoint with `--partition aws-us-gov` or `--partition aws-cn`. Account discovery through Organizations is deliberately excluded.

Reports saved with `--output` use mode `0600` and are replaced atomically. Live reports contain account metadata and must stay private; `/reports/` and `local*.yaml` are ignored by Git. Public examples must always use fake data.

Exit codes: **0** means collection completed, including when findings exist. **1** means an unsuppressed finding reached the optional `--fail-on critical|high|medium|low` threshold. **2** means invalid input or incomplete collection, which takes precedence over a finding threshold. JSON remains a report on stdout for partial collection in known accounts; startup errors use stderr and exit 2.

## Checks and severity logic

| ID | Check | Default severity and trigger |
| --- | --- | --- |
| IAM001 | Unused permissions | Medium: a granted service has no recorded access attempt for 90 days, or an older identity has no recorded attempt in the available tracking window. |
| IAM002 | Stale access keys | High: active key unused for 90 days. Medium: active key reaches its rotation age, even if recently used. Never-used keys get a creation-date grace period. Inactive keys are skipped. |
| IAM003 | Inactive users and roles | Medium: latest observed password, key, role, or service activity, or creation date, is at least 90 days old. Requires complete identity and Advisor observations. |
| IAM004 | Wildcard policies | High: literal global `Action: "*"`. Medium: literal global `Resource: "*"`. Checks Allow statements in local managed and user, role, and group inline policies, including unattached local policies. |
| IAM005 | Administrative or escalation candidates | Critical: AWS AdministratorAccess directly or through a group, or unconditional broad `iam:*` or `*`. High: conditional broad IAM grants or broad `iam:PassRole`, including matching action patterns. Effective privilege is not proven. |
| IAM006 | Missing MFA | High: console user without an assigned MFA device. Low: programmatic-only IAM user without one. Assigned MFA does not prove enforcement. |
| IAM007 | External role trust | High: external AWS principal without a mandatory, nonempty, specific ExternalId. Low: one with that guard. Wildcard principal is critical without the guard and high with it. Approved accounts can be excluded explicitly. |

Thresholds and reasoned, optionally expiring suppressions use [YAML](examples/config.yaml). Unknown keys, invalid thresholds, and blank reasons are rejected. Resource matching is case-sensitive glob matching. Suppressed findings remain in every report, retain their original severity, and do not count toward active severity totals or `--fail-on`. `trusted_accounts` changes the trust boundary, so review it carefully.

## Required IAM permissions

Attach [policy/auditor-read-only.json](policy/auditor-read-only.json) to the target audit role or current identity. Its eight actions retrieve the account inventory, user authentication metadata, key activity, MFA devices, and service-last-accessed reports. `GenerateServiceLastAccessedDetails` creates an asynchronous observation report; it does not change identities, permissions, keys, or trust. No policy simulation or automatic remediation is performed.

For multiple accounts, the caller also needs [an explicitly scoped AssumeRole permission](policy/assume-audit-role.example.json), and each target needs [a reviewed trust policy](policy/target-role-trust.example.json). Example accounts and role ARNs are fictional and must be replaced privately. The target role needs only the auditor policy; the caller does not need IAM write permissions. `GetCallerIdentity` identifies the current session and does not require a permission grant. See [the permission mapping](docs/permissions.md).

## JSON integration

The stable public contract is **schema_version `1.0.0`**. [JSON Schema](docs/report.schema.json) and [field semantics](docs/json-contract.md) document account collection status, finding IDs, severity ordering, evidence, and suppressions. Run `iam-audit schema` to export the installed contract. Dashboards must check `status` and `collection_issues` before displaying a clean result.

## Design decisions and honest limits

- Collection, rules, and rendering are separate. Rules have no network calls; tests start with Moto inventory and explicitly modeled historical activity. AWS responses are normalized to Pydantic models. SDK boundaries are dynamically typed, while the rest is checked with strict mypy.
- This is a static review aid, not a full IAM authorization engine. SCPs, resource policies, permission boundaries, session policies, explicit-deny interactions, condition semantics, and combined escalation paths are not evaluated. Findings on unattached policies are hygiene candidates, not exposure claims.
- Access Advisor is service-level, has a bounded tracking period, can lag, and includes denied attempts. Missing timestamps mean no observed attempt in that window, not proof that a permission has never been used. RoleLastUsed also has retention limits. `iam:PassRole` is not tracked by Access Advisor. Validate removals with owners and CloudTrail.
- Advisor polling is bounded to 30 attempts, one second apart, in the same role session. SDK requests have connection/read timeouts and bounded retries. Throttling, failed jobs, and denied calls yield explicit incomplete reports; missing activity never becomes a clean result. Large accounts take time because collection is sequential.
- AWS-managed policy documents other than the direct or group AdministratorAccess attachment check are excluded. IAM Identity Center, root credentials, service-specific credentials, SAML/OIDC trust conditions, `NotAction`, `NotResource`, and `NotPrincipal` are outside these seven rules. A mandatory ExternalId is useful for delegated access, but is not required for every valid trust relationship and is not a complete trust assessment.
- MFA assignment is distinct from MFA enforcement. No credential, policy, or trust changes are made. Rotation and deletion recommendations always require review.
- Demo and test validation do not establish behavior or permissions in a real AWS account. Live AWS validation has not been performed.

## Development and verification

```sh
make check
# Individual gates:
make lint
make typecheck
make test
```

CI runs Ruff, strict mypy, pytest with branch coverage of at least 85%, and all three demo outputs on Python 3.11, 3.12, 3.13, and 3.14 for every push and pull request. It needs no AWS credentials. Test sockets are blocked, and all seven rules have Moto-backed positive and negative cases. CI uploads test, coverage, schema, and demo artifacts for 14 days. See [verification notes](docs/verification.md).

MIT licensed. Contributions should include a focused test and use only fictional identifiers in fixtures and public reports.
