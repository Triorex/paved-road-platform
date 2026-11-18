#!/usr/bin/env bash
# Verify an image the way production does: signature, SBOM attestation and SLSA provenance,
# all tied to the central secure-build workflow identity.
#   scripts/verify.sh ghcr.io/triorex/payments-api@sha256:<digest>
set -euo pipefail
REF="${1:?usage: verify.sh <image@digest>}"
ID='^https://github\.com/[Tt]riorex/paved-road-platform/\.github/workflows/secure-build\.yml@.+$'
ISS=https://token.actions.githubusercontent.com
# cosign v2.6 matches the signing format (docs/adr/0002); run it from its pinned image.
COSIGN="docker run --rm -v $HOME/.docker/config.json:/root/.docker/config.json:ro ghcr.io/sigstore/cosign/cosign:v2.6.4@sha256:278d0b6c728608731d8fa2123c00c8b8dd6207aa53f079b195dea906b29ab0b2"

echo "== Signature";        $COSIGN verify "$REF" --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" \
                              | jq -r '.[0].optional | "signed by: \(.Subject)\nfrom repo: \(.githubWorkflowRepository) @ \(.githubWorkflowSha)"'
echo "== SBOM attestation"; $COSIGN verify-attestation "$REF" --type cyclonedx --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" \
                              | jq -r '.payload' | base64 -d | jq -r '"components in SBOM: \(.predicate.components | length)"'
echo "== SLSA provenance";  gh attestation verify "oci://$REF" --owner Triorex \
                              --signer-workflow Triorex/paved-road-platform/.github/workflows/secure-build.yml
