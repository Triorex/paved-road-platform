# AWS production target (design only, not applied)

What production on AWS looks like for the paved road. It is **scanned on every PR** (Trivy config
gates on high/critical, Checkov reports) but never applied in the demo, because there is no AWS
account wired up. In the demo, GHCR stands in for ECR and kind stands in for EKS.

| Resource | Why |
|---|---|
| GitHub OIDC provider | Workflows get short-lived AWS credentials; no access keys stored anywhere |
| `paved-road-deploy` role | Trusts **only** the `production` environment **and** the central `release.yml`, via the customised OIDC subject (`repo`, `context`, `job_workflow_ref`) |
| ECR repository per service | Immutable tags, scan on push, KMS encryption, lifecycle policy |
| KMS key | Customer-managed, rotation on |

The trust condition is the cloud half of the same idea Kyverno enforces in the cluster: only the
paved road can deploy, whatever repository the change came from.
