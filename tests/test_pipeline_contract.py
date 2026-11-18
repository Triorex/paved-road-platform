"""Contract test: the order of evidence in the caller template and the reusable workflows.

Production must only be reachable through staging and staging verification (admission + DAST),
and the release workflow must demand the evidence, not just rely on job ordering.
"""
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


def test_production_is_only_reachable_through_staging_verification():
    jobs = template()["jobs"]
    assert {"pr-security", "build", "staging", "staging-verify"} <= upstream(jobs, "production")
    assert "staging" in needs(jobs["staging-verify"])
    assert "pr-security" in needs(jobs["staging"])
    assert "staging-verify.yml" in jobs["staging-verify"]["uses"]


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
