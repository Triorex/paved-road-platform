#!/usr/bin/env bash
# Laptop demo: the same admission test CI runs, on a local kind cluster.
#
#   scripts/demo.sh ghcr.io/triorex/payments-api@sha256:<digest>      # signed by the paved road
#
# It then builds an image on this laptop, pushes it to the SAME registry path, and shows Kyverno
# denying it: the registry is trusted, but only images signed by the central workflow can run.
# Needs: docker, kind, kubectl, helm, gh (logged in with write:packages).
set -euo pipefail

SIGNED="${1:?usage: demo.sh <signed-image@digest>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${CLUSTER:-paved-road}"
CHART="${KYVERNO_CHART:-3.9.2}"
USER_NAME="$(gh api user --jq .login)"
TOKEN="$(gh auth token)"
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "kind cluster '$CLUSTER'"
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "Kyverno $CHART with registry credentials"
kubectl get ns kyverno >/dev/null 2>&1 || kubectl create namespace kyverno
kubectl -n kyverno create secret docker-registry ghcr --docker-server=ghcr.io \
  --docker-username="$USER_NAME" --docker-password="$TOKEN" --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install kyverno kyverno --repo https://kyverno.github.io/kyverno --version "$CHART" -n kyverno --wait --timeout 5m \
  --set 'existingImagePullSecrets[0]=ghcr' --set admissionController.replicas=1 \
  --set backgroundController.enabled=false --set cleanupController.enabled=false --set reportsController.enabled=false

step "Paved-road policies"
kubectl apply -f "$HERE/policies/kyverno/admission/" -f "$HERE/policies/kyverno/workload/"
kubectl wait --for=condition=Ready clusterpolicy --all --timeout=120s
kubectl get ns paved-road-demo >/dev/null 2>&1 || kubectl create namespace paved-road-demo
kubectl label namespace paved-road-demo paved-road.triorex.io/enforce=true --overwrite
kubectl -n paved-road-demo create secret docker-registry ghcr --docker-server=ghcr.io \
  --docker-username="$USER_NAME" --docker-password="$TOKEN" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n paved-road-demo delete pod --all --ignore-not-found >/dev/null

step "Build an image on this laptop and push it to the trusted registry path (no paved road)"
repo="${SIGNED%@*}"; repo="${repo%:*}"
laptop="$repo:laptop-$(date +%s)"
echo "$TOKEN" | docker login ghcr.io -u "$USER_NAME" --password-stdin >/dev/null
printf 'FROM cgr.dev/chainguard/static@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9\nUSER 65532\n' \
  | docker build --platform linux/amd64 -q -t "$laptop" - >/dev/null
docker push -q "$laptop" >/dev/null
UNSIGNED="$(docker inspect --format '{{index .RepoDigests 0}}' "$laptop")"
echo "laptop image: $UNSIGNED"

step "Admission cases"
bash "$HERE/scripts/admission_cases.sh" "$SIGNED" "$UNSIGNED" 8080
