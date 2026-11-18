# Paved Road: build plan

Approved by Blaise on 2026-11-18. This file is the source of truth for the build, so any session can pick it up.
Design document: [`design.html`](design.html) (published copy: https://claude.ai/artifact/Bk7wjxekLEHcUctwuyk3KH).

## Goal

A working, public reference implementation of an enterprise secure software supply chain on GitHub Actions:
one central platform repo of reusable workflows that protects a fleet of about 80 repositories,
from the developer's laptop to production.

## Decisions

| Decision | Choice |
|---|---|
| GitHub home | Organization `Triorex` (GitHub Team plan), public repos with hardening (decided 2026-11-18 after reviewing the private-repo trade-offs: on Team, private repos lose free GHAS, artifact attestations and environment reviewers) |
| Repos | `paved-road-platform` (central), `payments-api` (Python FastAPI, golden template), `orders-api` (Node.js Express) |
| Registry | GHCR (the local AWS CLI cannot run on this Mac) |
| JFrog | Design and config only; live `curation_check.py` stands in |
| AWS, Falco/Wiz, self-hosted runners | Design only |
| Org governance (Team plan, approved 2026-11-18) | Live and as code in `governance/`: teams, custom properties, `paved-road-baseline` security configuration, Actions allowlist with SHA pinning required, OIDC subject with `job_workflow_ref`, org ruleset targeting `paved-road=true` (required check `pr-security / gate`, CodeQL high+ blocks). Ruleset rule requiring the central workflow may need Enterprise; tested in Step 3 |
| Tool versions | 14-day release cooldown: newest release before 2026-11-04, actions pinned by commit SHA, images by digest |
| Signing | cosign v2.6.4 (legacy format Kyverno 1.19 verifies); see `docs/adr/0002` |
| Signing | cosign keyless (Sigstore) + GitHub artifact attestations; signer identity = central `secure-build.yml` |
| Admission | Kyverno `verifyImages` in a throwaway kind cluster in CI, and on the laptop for the demo |
| Fleet | `fleet/inventory.yaml` of 80 repos; onboarding live on 2, dry-run on 78 |

## Local layout

```
07-paved-road-secure-supply-chain/
├── paved-road-platform/    central repo
├── payments-api/           consumer repo 1
├── orders-api/             consumer repo 2
└── paved-road.code-workspace
```

## Pipeline

```
DEV MACHINE   pre-commit: gitleaks, Semgrep, Hadolint, detect-private-key
PR GATES      pr-security.yml: secrets (GHAS + gitleaks) · SAST (CodeQL, Semgrep, Bandit)
              · SCA (dependency review, OSV-Scanner, Trivy fs, licenses) · curation
              · IaC (Checkov, Trivy config) · workflow lint (zizmor, actionlint, SHA pins)
              · policy (Kyverno CLI) · exception expiry
BUILD         secure-build.yml: unit tests → Hadolint → build on Chainguard → push GHCR by digest
              → Trivy image + Dockle → DAST (OWASP ZAP) → SBOM (Syft) → cosign sign + attest
              → SLSA provenance          (signing runs last: a signature means every gate passed)
ADMISSION     admission-test.yml: kind + Kyverno: signed admitted, unsigned denied
RELEASE       release.yml: staging → production (required reviewer), attestations verified, promote by digest
OPERATE       vuln-triage.yml (KEV + EPSS → issues with SLA) · scorecard.yml · Dependabot · fleet report
```

## Steps and status

- [x] **0. Setup**: folder, design doc, tools (kind, cosign, syft, trivy, helm), Docker, `gh auth login`, VS Code
- [x] **1. Platform repo**: security config, reusable workflows, Kyverno policies, scripts, governance, fleet tooling, Terraform and JFrog design. Local checks green: 18 unit tests, 12 Kyverno tests, actionlint, zizmor, pin check, Trivy config, gitleaks, Semgrep/Bandit. Not committed yet (commit + push at Step 3, with approval)
- [ ] **2. Consumer repos** (one at a time)
  - [x] payments-api: FastAPI on Python 3.15, hash-locked deps, Chainguard image with 0 CVEs, k8s manifests. Local gates green: 6 tests, curation (24 pkgs), Trivy fs/config/image, Hadolint, Dockle, Kyverno, gitleaks, Semgrep/Bandit, ZAP API scan (0 FAIL / 119 PASS). Fixes found by the gates: pip's vendored setuptools CVE (pip removed from runtime), Dependabot docker cooldown (template fixed)
  - [ ] orders-api
- [x] **3. Publish** (2026-11-18, public repos + hardening): org hardening (no member repo creation, outside-contributor workflow approval, 7-day retention), teams, custom properties, `paved-road-baseline` security configuration (public repos only, so GHAS never bills a private repo), Actions allowlist with SHA pinning required, OIDC subject. Platform published and released as v1.0.0 (`971de5ed`); first platform-ci run green (14 jobs, 8 tools in the Security tab). payments-api onboarded live (properties, teams, staging + production with appsec reviewer) and pinned to v1.0.0. Org ruleset applied last. Commits use the GitHub noreply address
- [ ] **4. First green run**: PR through all gates; merge → build, DAST, SBOM, sign, attest; verify
- [ ] **5. Admission**: CI test and local kind demo
- [ ] **6. Release and operate**: staging → production; triage; Scorecard; fleet onboarding and report
- [ ] **7. Docs and rehearsal**: threat model, procedure, demo script, roadmap, standards, runbooks, ADRs

## Demo pull requests

1. Known-vulnerable dependency → blocked by dependency review and OSV-Scanner
2. SQL injection → flagged by CodeQL and Semgrep
3. Hardcoded test secret → blocked by gitleaks
4. Privileged pod manifest → blocked by the Kyverno CLI

## Checkpoints that need the org owner

- Approve the first push to public repos
- Make the GHCR package public if it defaults to private
- Approve the production deployment (part of the demo)
