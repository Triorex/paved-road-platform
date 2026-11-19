# Threat model: the Paved Road supply chain

**Version:** platform v1.2.0 (dev, staging, production) · **Method:** STRIDE per trust boundary · **Owner:** AppSec · **Reviewed:** 2026-11-19

The system being protected is the path from a developer's change to a running container: source, PR gates,
build, signing, registry, promotion and admission. The application's own threat model (payments-api) is out
of scope. Every control below names the file that implements it, so each claim can be checked.

## Assets

| Asset | Why it matters |
|---|---|
| Signing identity (`secure-build.yml` OIDC token, Fulcio certificate) | Whoever can sign as the central workflow can deploy anything |
| The platform repo (`paved-road-platform`) | One change reaches every repo in the fleet: highest-value target |
| Image digests and their attestations | The only evidence production trusts |
| Environment approvals (QA, appsec) and deployment history | Decide what reaches staging and production, and when |
| `GITHUB_TOKEN` and job permissions | Write access to packages, releases and code scanning |
| Dependencies and base images | Code we run but didn't write |

## Trust boundaries

```
 developer laptop ──► GitHub (PR, fork PRs = untrusted) ──► app repo CI ──calls──► platform reusable workflows (pinned SHA)
                                                                │                        │
                                                   public registries (PyPI, npm,          ├──► Sigstore (Fulcio, Rekor)
                                                   cgr.dev, GitHub Actions)               ├──► GHCR (images, attestations)
                                                                                          └──► staging / production (approver)
                                                                                                        │
                                                                                               cluster admission (Kyverno)
```

1. **Laptop → GitHub:** anything a developer pushes.
2. **PR code → workflows:** PR content, titles and branch names are attacker-controlled on a public repo.
3. **App repo → platform:** the app chooses which platform commit to call and with what inputs.
4. **Runner → internet:** dependencies, actions and tools are fetched at build time.
5. **CI → registry → cluster:** the artifact leaves the build; tags are mutable, digests are not.
6. **Branch → dev:** any branch can be built, signed and deployed to dev on demand, before review.
7. **Human approvals:** QA signs off staging; appsec approves production.

## Threats and controls

Status: **Live** = enforced in the running platform · **Partial** = enforced with a known gap · **Design** = not implemented.

### Spoofing

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| S1 | An image built outside the paved road (laptop, forked pipeline) is deployed as if legitimate | Keyless signature whose identity is the central `secure-build.yml`; Kyverno admits only that issuer and subject; release re-verifies with `--signer-workflow` | `policies/kyverno/admission/verify-images.yaml`, `release.yml` | Live |
| S2 | An app repo forges DAST or promotion evidence | Evidence is checked with `gh attestation verify --signer-workflow` against the platform's `staging-verify.yml` / `release.yml`; an app repo cannot sign as those | `release.yml` | Live |
| S3 | An app repo calls an **old, vulnerable** platform commit, which still signs as `secure-build.yml` | Fleet report flags repos behind the current release; Dependabot proposes upgrades; beyond dev, provenance must also come from the app's `main` (`--source-ref`) | `fleet/compliance_report.py`, `release.yml` | Partial: verifiers accept any commit of the platform repo (`@.+`); restrict to released commits next |
| S4 | Commit authorship or trailers misrepresent who wrote a change | Noreply emails; org ruleset rejects disallowed author emails and trailers | `governance/org-ruleset.json` | Partial: commit signing not required |

### Tampering

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| T1 | Malicious, typosquatted or brand-new package | Curation gate (OSV malicious advisories, releases younger than 7 days, license allowlist), dependency review, SCA, hash-pinned requirements, Dependabot 7-day cooldown | `scripts/curation_check.py`, `pr-security.yml`, `fleet/templates/dependabot-*.tmpl` | Live (JFrog front door: Design) |
| T2 | Compromised third-party action (the tj-actions pattern) | Org policy requires SHA pins; `check_pinned_actions.py` and zizmor (impostor commits) in every PR; harden-runner egress monitoring | `governance/actions-policy.json`, `pr-security.yml` | Partial: egress is audited, not blocked |
| T3 | Poisoned build cache gets signed with the artifact | No shared caches in the signing workflow | `secure-build.yml` header | Live |
| T4 | Image swapped after signing (tag moved, index re-wrapped) | Everything addressed by digest; exact-copy promotion asserts the tag resolves to the signed digest; Kyverno `mutateDigest` + `verifyDigest` | `release.yml`, `verify-images.yaml` | Live |
| T5 | Script injection through PR titles, branch names or workflow inputs | Inputs passed through `env`, never interpolated into `run:`; zizmor gate; `permissions: {}` by default | all workflows, `pr-security.yml` | Live |
| T6 | Malicious or broken change to the platform repo reaches 80 repos | PR + `pr-security / gate` required; release candidates proven in ring 0 before a final release; contract tests; consumers pin a SHA | `governance/org-ruleset.json`, `promote-release.yml`, `tests/` | Partial: code-owner review is not required (single maintainer; set to 1+ with code owners in an enterprise) |
| T7 | Policy or scripts drift from the workflow version the app pinned | Each workflow checks out the platform at `job_workflow_sha` from its own OIDC token | all reusable workflows | Live |

### Repudiation

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| R1 | No record of who approved production or what shipped | Environment approvals; signed promotion attestation per environment; GitHub Release only after production, naming the approver; Rekor transparency log | `release.yml`, `record-release.yml` | Live |
| R2 | A risk exception with no owner or end date | Exceptions need owner, reason and expiry (max 90 days); expired exceptions fail CI | `scripts/check_exceptions.py`, `.security/exceptions.yaml` | Live |
| R3 | No proof that QA tested and accepted what shipped | QA approval in the `qa-signoff` environment produces a signed attestation naming the approvers and the API pentest result; production verifies it | `qa-signoff.yml`, `release.yml` | Live |

### Information disclosure

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| I1 | Secret committed or pushed | gitleaks pre-commit hook and CI scan of full history; GHAS push protection | `.pre-commit-config.yaml`, `pr-security.yml`, security configuration | Live |
| I2 | Long-lived credentials stolen from CI | OIDC only; no stored registry, signing or cloud keys; per-job least privilege; `persist-credentials: false` | all workflows, `governance/oidc-subject.json` | Live |
| I3 | Public logs and artifacts leak internal detail | Summaries show counts and rule IDs only; 7-day log and artifact retention; noreply commit emails | `governance/org-hardening.json` | Live |

### Denial of service

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| D1 | Sigstore or Rekor outage blocks every release | Target: break-glass with an audit trail; private Sigstore or key-based signing for critical paths | not yet written | Design |
| D2 | A platform defect stops the whole fleet | Rollout rings, release candidates, contract tests, `[WITHDRAWN]` releases instead of silent deletes | `promote-release.yml`, `tests/` | Live |
| D3 | Noisy scanners stall delivery | Each gate runs in audit or enforce from one policy file; time-bound exceptions | `security/security-policy.yml` | Live |

### Elevation of privilege

| # | Threat | Control | Where | Status |
|---|---|---|---|---|
| E1 | A fork PR runs with write tokens or secrets | No `pull_request_target`; approval required for all outside-contributor workflows; PR jobs hold read-only tokens (plus `security-events: write`) | `governance/org-hardening.json`, `pr-security.yml` | Live |
| E2 | A staging caller is granted production-level write | Release recording split into `record-release.yml`, called only by production; a contract test checks caller permissions | `record-release.yml`, `tests/` | Live |
| E3 | Privileged or root container escapes to the node | Kyverno baseline: non-root, no privilege escalation, not privileged, read-only root filesystem, all capabilities dropped, no `:latest`; Chainguard runtime image has no shell or package manager | `policies/kyverno/workload/workload-baseline.yaml`, app `Dockerfile` | Live |
| E4 | An older commit is promoted and silently rolls back a fix | Forward-only check against the deployed commit; one promotion per environment at a time | `release.yml` | Live |
| E5 | The author of a change dismisses their own security alert | Ruleset blocks merge until review threads are resolved; AppSec triages code-scanning alerts | `governance/org-ruleset.json` | Partial: process, not technically enforced on the Team plan |
| E6 | An unreviewed branch build, deployed to dev for testing, is promoted to staging or production | Staging, QA sign-off and production environments allow `main` only; the caller skips staging off `main`; `release.yml` refuses non-main runs and verifies the provenance was built from `refs/heads/main` | `governance/environments.json`, `release.yml` | Live |
| E7 | Production approved before QA testing or the API pentest | Production requires the QA sign-off attestation; QA sign-off requires staging DAST and, when `gates.api_pentest.mode` is `enforce`, a passing pentest attestation | `qa-signoff.yml`, `security/security-policy.yml` | Live (pentest gate off; workflow not built yet) |

## Residual risks, in priority order

1. **S3:** verifiers accept a signature from any commit of the platform repo. Next: verify the signer's source ref against released tags (`--source-ref` / `--signer-digest`), and alert on repos pinned below the supported window.
2. **T2:** runner egress is audited, not blocked. Next: move harden-runner to `block` with the allowlist learned from audit logs.
3. **T6 / E5:** one maintainer, so code-owner review and separation of duties rely on process. In an enterprise: required code-owner review on the platform repo and a separate AppSec group for alert dismissal.
4. **D1:** no break-glass path is implemented yet.
5. **E7:** the API pentest gate exists but is `off`, and the pentest workflow (`api-pentest.yml`) is not built yet.
6. **Runtime:** nothing watches running containers (Falco or Wiz are design only), so a post-admission compromise would go unseen.

## Review triggers

Revisit this model when: a new trust boundary appears (new registry, cloud, runner type), a control moves
between audit and enforce, a new reusable workflow is added, or an incident or near miss touches the supply chain.
