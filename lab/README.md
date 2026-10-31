# Controlled validation lab

The default plan creates nothing. This configuration is an opt-in IAM-only sandbox fixture, never invoked by the auditor or CI. It creates a user with no keys, password or MFA, a narrow boundary intersecting an administrative inline grant, and two roles with broad PassRole policies and contrasting ExternalId conditions. Trust points to the specified sandbox itself, avoiding an unintended external principal.

After explicit sandbox authorization, run `terraform init`, `terraform plan -var sandbox_account_id=YOUR_ACCOUNT -var enable_lab=true`, review the plan, then apply that exact plan. Use existing short-lived operator credentials. Record auditor JSON privately, inspect boundary context, and destroy only these prefixed resources after verification. Never deploy into production.

Stale timestamps cannot safely be manufactured in live IAM. The offline Moto/Stubber demo supplies historical keys and inactivity; its external-account trust is fictional. OIDC positive and adversarial conditions use offline rule tests. No access keys, login passwords, identity providers, workloads, analyzers, or billable services are created here. Terraform state remains private and ignored. No live execution of this lab has been performed.
