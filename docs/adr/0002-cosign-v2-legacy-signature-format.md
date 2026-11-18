# ADR 0002: Sign with cosign v2.6 (legacy signature format) for now

- Status: accepted
- Date: 2026-11-18
- Deciders: AppSec, Platform

## Context

The paved road signs every image keylessly with Sigstore and Kyverno verifies the signature at
admission. cosign v3 (current: v3.1.4) always writes the new Sigstore bundle format and removed
the flags that produced the older `.sig`/`.att` tag format. The cluster runs Kyverno 1.19.2, and
we have not validated that its `verifyImages` rule reads v3 bundles from GHCR.

A signature format mismatch fails closed: every deploy would be denied.

## Decision

Pin cosign **v2.6.4** in `secure-build.yml` and `release.yml`. It defaults to the legacy format,
which Kyverno 1.19 verifies, and it is inside the 14-day release cooldown we apply to all tooling.
SLSA provenance uses GitHub artifact attestations, which are already Sigstore bundles and are
verified with `gh attestation verify` in `release.yml`, so provenance is not affected.

## Consequences

- Signing and admission work today with no format risk.
- We carry a known upgrade: move to cosign v3 bundles once the Kyverno upgrade that reads them
  has passed the admission test (admission-test.yml) in ring 0. The admission test exists
  precisely so this kind of upgrade is proven before it reaches the fleet.
- cosign v2 receives security fixes on the 2.6 line; Dependabot and the platform's own release
  process track it.
