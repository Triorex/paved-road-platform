"""Contract test: the order of evidence in the caller template and the reusable workflows.

Production must only be reachable through staging and staging verification (admission + DAST),
and the release workflow must demand the evidence, not just rely on job ordering.
"""
import json
import os
import re

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")


def load(path):
    with open(os.path.join(ROOT, path)) as fh:
        return yaml.safe_load(fh)


def template():
    with open(os.path.join(ROOT, "fleet", "templates", "ci.yml.tmpl")) as fh:
        text = fh.read().replace("{{PLATFORM_SHA}}", "0" * 40)
    return yaml.safe_load(re.sub(r"\{\{\w+\}\}", "x", text))


def needs(job):
    n = job.get("needs", [])
    return {n} if isinstance(n, str) else set(n)


def upstream(jobs, name):
    seen, todo = set(), [name]
    while todo:
        for dep in needs(jobs[todo.pop()]):
            if dep not in seen:
                seen.add(dep)
                todo.append(dep)
    return seen


def test_production_is_only_reachable_through_dev_staging_verification_and_qa():
    jobs = template()["jobs"]
    assert {"pr-security", "build", "dev", "staging", "staging-verify", "qa-signoff"} <= upstream(jobs, "production")
    assert "dev" in needs(jobs["staging"])
    assert "staging" in needs(jobs["staging-verify"])
    assert "staging-verify" in needs(jobs["qa-signoff"])
    assert "qa-signoff" in needs(jobs["production"])
    assert "pr-security" in needs(jobs["staging"])
    assert "staging-verify.yml" in jobs["staging-verify"]["uses"]
    assert "qa-signoff.yml" in jobs["qa-signoff"]["uses"]


def test_branches_reach_dev_on_demand_but_never_staging():
    t = template()
    triggers = t.get("on", t.get(True))  # PyYAML reads the bare key `on` as True
    assert "workflow_dispatch" in triggers
    jobs = t["jobs"]
    assert "pr-security" not in needs(jobs["dev"])  # developers get dev without waiting for PR gates
    assert jobs["staging"]["if"] == "github.ref == 'refs/heads/main'"


def test_qa_signoff_is_a_reviewed_environment_and_checks_the_pentest_gate():
    job = load(".github/workflows/qa-signoff.yml")["jobs"]["signoff"]
    assert job["environment"]["name"] == "qa-signoff"
    text = open(os.path.join(ROOT, ".github", "workflows", "qa-signoff.yml")).read()
    assert "api_pentest" in text and "attestations/qa-signoff/v1" in text
    envs = json.load(open(os.path.join(ROOT, "governance", "environments.json")))
    assert envs["qa-signoff"]["reviewer_teams"] == ["qa"] and envs["qa-signoff"]["main_only"]
    assert envs["dev"]["main_only"] is False and envs["staging"]["main_only"] and envs["production"]["main_only"]
    policy = load("security/security-policy.yml")
    assert policy["gates"]["api_pentest"]["mode"] in {"off", "audit", "enforce"}


def test_build_does_not_wait_for_the_pr_gates_on_push():
    assert "pr-security" not in needs(template()["jobs"]["build"])


def test_signing_waits_for_tests_and_image_scan_and_dast_left_the_build():
    jobs = load(".github/workflows/secure-build.yml")["jobs"]
    assert {"test", "image-scan"} <= needs(jobs["sign"])
    assert "dast" not in jobs


def test_release_demands_dast_evidence_and_forward_only_promotion():
    text = open(os.path.join(ROOT, ".github", "workflows", "release.yml")).read()
    promote = load(".github/workflows/release.yml")["jobs"]["promote"]
    names = [s.get("name", "") for s in promote["steps"]]
    assert "Require passing DAST evidence from staging" in names
    assert "Refuse to move the environment backwards" in names
    assert names.index("Refuse to move the environment backwards") < names.index(
        "Promote by digest (exact copy, no rebuild, no re-wrap)")
    assert "staging-verify.yml" in text and "attestations/dast/v1" in text
    assert promote["concurrency"]["cancel-in-progress"] is False


def test_release_requires_qa_and_main_builds_beyond_dev():
    promote = load(".github/workflows/release.yml")["jobs"]["promote"]
    steps = {s.get("name", ""): s for s in promote["steps"]}
    assert steps["Require QA sign-off from staging"]["if"] == "inputs.environment == 'production'"
    assert steps["Only main-branch builds go beyond dev"]["if"] == "inputs.environment != 'dev'"
    assert steps["Refuse to move the environment backwards"]["if"] == "inputs.environment != 'dev'"
    assert "--source-ref" in steps["Verify SLSA provenance and SBOM attestations (GitHub)"]["run"]
    prior = promote["env"]["REQUIRED_PRIOR"]
    assert "'staging'" in prior and "'dev'" in prior
