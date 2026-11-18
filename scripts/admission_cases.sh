#!/usr/bin/env bash
# Admission test cases, shared by CI (staging-verify.yml) and the laptop demo (scripts/demo.sh).
# Usage: admission_cases.sh <signed-image@digest> <unsigned-image@digest> [container-port]
set -uo pipefail

SIGNED="$1"
UNSIGNED="$2"
PORT="${3:-8080}"
NS="${NS:-paved-road-demo}"
pass=0
fail=0
report="| Case | Expected | Result |\n|---|---|---|"

manifest() { # name image privileged
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
spec:
  imagePullSecrets: [{ name: ghcr }]
  containers:
    - name: app
      image: $2
      ports: [{ containerPort: $PORT }]
      securityContext:
        runAsNonRoot: $([ "$3" = true ] && echo false || echo true)
        allowPrivilegeEscalation: $3
        privileged: $3
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
EOF
}

expect() { # case-name expected(admit|deny) name image privileged
  local out rc
  out=$(manifest "$3" "$4" "$5" | kubectl apply -f - 2>&1); rc=$?
  if { [ "$2" = admit ] && [ $rc -eq 0 ]; } || { [ "$2" = deny ] && [ $rc -ne 0 ]; }; then
    pass=$((pass + 1)); result=$([ "$2" = admit ] && echo "✅ admitted" || echo "✅ denied")
  else
    fail=$((fail + 1)); result="❌ unexpected"
  fi
  echo "---- $1: expected $2, kubectl exit $rc"
  echo "$out" | sed 's/^/     /' | head -12
  report="$report\n| $1 | $2 | $result |"
}

expect "Signed by the paved road"        admit signed-app   "$SIGNED"   false
expect "Unsigned image, same registry"   deny  unsigned-app "$UNSIGNED" false
expect "Signed image, privileged + root" deny  root-app     "$SIGNED"   true

summary="## Admission test\n\n$report\n\n**$pass passed, $fail failed**"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%b\n' "$summary" >> "$GITHUB_STEP_SUMMARY"; else printf '%b\n' "$summary"; fi
kubectl -n "$NS" get pod signed-app -o jsonpath='{.spec.containers[0].image}{"\n"}' 2>/dev/null | sed 's/^/Admitted image (tag rewritten to digest by Kyverno): /'
[ $fail -eq 0 ]
