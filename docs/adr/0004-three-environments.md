# ADR 0004: Three environments: dev, staging, production

- Status: accepted
- Date: 2026-11-19

## Context

With two environments, developers had nowhere to run their code before it entered the release
path. Staging was doing three jobs at once: integration testing, QA, and security validation. QA
also had no formal place in the flow: the production approval covered both "QA is happy" and
"release this". The roadmap adds API penetration testing before production, and that needs a
defined home.

## Decision

```
any branch (Run workflow) ─► build ─► DEV
merge to main ─────────────► build ─► DEV ─► STAGING ─► STAGING VERIFY ─► QA SIGN-OFF ─► PRODUCTION ─► release
```

| Environment | Purpose | Entry rule | Evidence written |
|---|---|---|---|
| dev | Developers test their code | Signed build (tests and image scan passed), any branch, no approval | `promotion/v1` (dev) |
| staging | QA and security validation | Build of `main`, PR gates passed, signed dev promotion | `promotion/v1` (staging) |
| staging verify | Admission cases and DAST against the deployed workload | Automatic after staging | `dast/v1` |
| QA sign-off | QA approves after testing in staging | Required reviewer: `qa` team; staging verify passed; API pentest gate | `qa-signoff/v1` |
| production | Release | Required reviewer: `appsec`; staging, DAST and QA evidence; forward-only | `promotion/v1` (production), then the GitHub Release |

- **Branch builds never leave dev.** Staging, QA sign-off and production environments allow
  `main` only, the caller skips staging off `main`, and `release.yml` verifies the provenance
  was built from `refs/heads/main` (`gh attestation verify --source-ref`). This also narrows the
  "any platform commit can sign" residual risk: a signature alone no longer gets past dev.
- **Dev may move backwards.** Developers switch dev between branches; the forward-only check
  applies to staging and production only.
- **QA is evidence, not a comment.** The QA approval produces a signed attestation that names
  the approvers and the pentest result. Production verifies it like any other evidence.
- **API pentest is a policy switch.** `gates.api_pentest.mode` in `security-policy.yml`
  (`off` today). At `enforce`, QA cannot sign off without a passing signed pentest attestation
  (`api-pentest/v1`) for the digest, so production inherits the requirement without a pipeline
  change. The pentest workflow itself (`api-pentest.yml`) is the next piece of work.
- **What "deploy" means here** is unchanged: an environment tag on the exact signed digest, a
  GitHub deployment record and signed evidence, with kind as the throwaway cluster. Persistent
  dev and staging clusters (EKS namespaces) remain design.

## Consequences

- One more approval per release (QA), and one more job; push to dev takes about 3 minutes and
  push to staging about 4.
- Registry cleanup keeps the `dev` tag, so the image a developer is testing is never deleted.
- A team without a QA function would need the `qa` team populated or the gate removed from its
  caller; the template ships with it on.
- `security-policy.yml` values that read as YAML 1.1 booleans (`off`, `on`, `yes`) must be quoted:
  the contract test caught `mode: off` parsing as `false` in Python while `yq` read `"off"`.
- Ring 0 caught a defect on `v1.2.0-rc.1`: `qa-signoff.yml` read the DAST attestation from the
  private registry before logging in, so QA sign-off failed closed after approval. Fixed in
  `v1.2.0-rc.2`. A contract test now requires a registry login before any step that verifies an
  attestation from the registry, in every workflow.
