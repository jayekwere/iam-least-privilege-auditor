# Verification

Run `make check` to execute Ruff lint and formatting, strict mypy across source and tests, and pytest with branch coverage. The coverage gate is 85%; no source files or branches are excluded. Tests prevent socket connections and use Moto IAM inventory, with Botocore Stubber or explicit SDK error doubles for unsupported activity observations and failure cases.

Local verification on October 28, 2026, with Python 3.14.6 passed 63 tests. All three CLI demo formats were executed, and the first-run `make demo` installation and subsequent offline `make demo` both succeeded. A fresh demo JSON run matched the committed example exactly. The suite includes real Boto3 STS calls intercepted by Moto that isolate inventory in two fictional accounts, and checks that duplicate group grants do not duplicate findings. See the [captured local gate output](evidence/local-verification.txt) for the measured coverage and command results.

The [hosted verification run for 9710fe0](https://github.com/jayekwere/iam-least-privilege-auditor/actions/runs/40783488736) passed on Python 3.11, 3.12, 3.13, and 3.14 with the earlier 61-test suite. Later commits run the expanded suite through the same [GitHub Actions workflow](https://github.com/jayekwere/iam-least-privilege-auditor/actions/workflows/ci.yml). The badge and latest run give the current branch status rather than freezing that status in prose.

The workflow runs on Python 3.11 through 3.14 and retains JUnit, coverage XML, schema, and demo artifacts for 14 days. It checks that the demo has 17 findings and that the exported schema matches the committed schema. All account-owned identifiers in public examples are fictional.

Coverage is evidence of exercised branches, not proof of effective IAM authorization, AWS service compatibility, or live account permission sufficiency. No real AWS account was used, no real account report was published, and no live credentials were requested or saved. The demo clock is fixed and its historical activity observations are explicitly synthetic.
