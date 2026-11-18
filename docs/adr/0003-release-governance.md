# ADR 0003: Only proven releases reach production

- Status: accepted
- Date: 2026-11-18

## Context

Two problems surfaced once the pipeline ran end to end:

1. **Tags did not match what was signed.** `docker buildx imagetools create --tag` wraps a single
   manifest in a new OCI image index by default. The `staging` and `production` tags therefore
   pointed at an unsigned wrapper digest, not the signed image that passed the gates.
2. **Releases came before proof.** Platform v1.0.0 and v1.0.1 were published as final releases
   and both turned out defective in ring 0. Every app build also leaves an image behind, so the
   registry fills with artifacts that never reached an environment.

## Decision

**App releases**
- Promote by exact copy (`--prefer-index=false`) and assert the tag resolves to the signed digest.
- Each promotion writes a signed promotion attestation (`https://triorex.dev/attestations/promotion/v1`)
  for that digest. Production refuses a digest without a signed promotion to staging.
- A GitHub Release is created only after production promotion, with the digest, approver and run.
- A weekly registry cleanup removes images never promoted (keeps promoted, newest 10, recent).

**Platform releases**
- New versions ship as release candidates (`vX.Y.Z-rc.N`, GitHub pre-release) pinned by ring 0 only.
- `promote-release.yml` creates the final `vX.Y.Z` on the same commit only when platform-ci passed
  and every existing ring-0 repo has a successful production deployment pinned to the candidate.
- Defective releases are withdrawn, not deleted: marked pre-release and titled `[WITHDRAWN]`, and the
  fleet report flags any repo still pinned to them.

**Pipeline order and evidence (v1.1.0)**
- DAST runs after staging, against the workload deployed from the app's own manifests at the
  promoted digest (`staging-verify.yml`), and writes a signed DAST attestation
  (`https://triorex.dev/attestations/dast/v1`). Production refuses a digest without a passing one.
- The admission test moved into the same post-staging job: deploying to the policy-enforcing
  cluster is the admission test.
- An environment never moves backwards: the commit must equal or descend from the commit already
  deployed there (GitHub compare API). Rollback is a revert on main that rolls forward. Promotions
  to one environment are serialised with a concurrency group. Found when two Dependabot merges
  17 seconds apart both raced to production.
- Push builds no longer wait for the re-run of pr-security; it gates the staging promotion instead.
  Unit tests run alongside the build; signing waits for both. Time to staging: ~9-11 min → ~4-5 min.

## Consequences

- The releases lists (platform and app) contain only what was proven in production.
- Production cannot be reached by skipping staging or by promoting an arbitrary digest.
- Target state: Kyverno in production namespaces also requires the production promotion
  attestation, once Kyverno reads GitHub attestation bundles (see ADR 0002).
