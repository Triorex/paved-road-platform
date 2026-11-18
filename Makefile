# Paved Road platform: local developer and operator commands.
PY := .venv/bin/python
KYVERNO ?= kyverno

.PHONY: setup test lint policy-test governance-plan governance-apply fleet-plan fleet-report demo verify

setup:            ## create the virtualenv with pinned tooling
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements-dev.txt

test:             ## unit tests for every gate script
	$(PY) -m pytest -q tests

lint:             ## the same workflow checks the PR gate runs
	docker run --rm -v "$$PWD:/repo" -w /repo rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
	$(PY) scripts/check_pinned_actions.py --root .

policy-test:      ## Kyverno policy unit tests
	$(KYVERNO) test policies/kyverno/tests/

governance-plan:  ## show what org governance would change (read-only)
	$(PY) governance/apply_governance.py

governance-apply: ## apply org governance (teams, properties, security config, actions policy, OIDC, ruleset)
	$(PY) governance/apply_governance.py --apply

fleet-plan:       ## plan onboarding for all 80 repos; needs PLATFORM_SHA and PLATFORM_VERSION
	$(PY) fleet/onboard.py --platform-sha $(PLATFORM_SHA) --platform-version $(PLATFORM_VERSION)

fleet-report:     ## adoption and compliance report across the fleet
	$(PY) fleet/compliance_report.py --output fleet-report.md

demo:             ## laptop admission demo; needs SIGNED=ghcr.io/triorex/<app>@sha256:...
	bash scripts/demo.sh $(SIGNED)

verify:           ## verify signature, SBOM attestation and provenance; needs REF=...
	bash scripts/verify.sh $(REF)
