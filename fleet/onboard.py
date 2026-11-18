#!/usr/bin/env python3
"""Onboard repositories from fleet/inventory.yaml onto the paved road.

Because the ruleset and security configuration live at org level, onboarding a repo is small:
  1. set its custom properties (paved-road=true, ring, risk-tier, language, owner-team)
     -> the org ruleset and the paved-road-baseline security configuration now apply
  2. grant team access (owner team write, appsec + platform write for CODEOWNERS reviews)
  3. create the staging and production environments (production requires an appsec reviewer)
  4. if the repo has no paved-road caller yet, open an onboarding PR with the rendered templates

Dry-run by default. Repos marked `real: false` model the enterprise fleet and are only planned.

  python fleet/onboard.py --platform-sha <sha> --platform-version v1.0.0            # plan all 80
  python fleet/onboard.py --platform-sha <sha> --platform-version v1.0.0 --apply    # apply to real repos
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from ghapi import Gh, GhError  # noqa: E402
from prlib import load_yaml  # noqa: E402

LANGS = {
    "python": {"codeql": '["python","actions"]', "install": "pip install -r requirements.txt -r requirements-dev.txt",
               "test": "python -m pytest -q", "dast": "api", "dependabot": "pip", "build": True},
    "node":   {"codeql": '["javascript-typescript","actions"]', "install": "npm ci", "test": "npm test",
               "dast": "baseline", "dependabot": "npm", "build": True},
    "java":   {"codeql": '["java-kotlin","actions"]', "build": False},
    "go":     {"codeql": '["go","actions"]', "build": False},
    "dotnet": {"codeql": '["csharp","actions"]', "build": False},
}


def render(name: str, values: dict) -> str:
    with open(os.path.join(HERE, "templates", name), encoding="utf-8") as fh:
        text = fh.read()
    for key, val in values.items():
        text = text.replace("{{" + key + "}}", str(val))
    return text


def files_for(repo: dict, sha: str, version: str) -> dict[str, str]:
    lang = LANGS[repo["language"]]
    vals = {"PLATFORM_SHA": sha, "PLATFORM_VERSION": version, "OWNER_TEAM": repo["owner_team"],
            "CODEQL_LANGUAGES": lang["codeql"], "IMAGE_NAME": repo["name"], "LANGUAGE": repo["language"],
            "INSTALL": lang.get("install", ""), "TEST": lang.get("test", ""), "DAST_MODE": lang.get("dast", "baseline")}
    ci = render("ci.yml.tmpl", vals)
    if not lang["build"]:  # PR gates only until secure-build supports this stack (roadmap)
        ci = ci.split("\n  build:\n", 1)[0] + "\n"
    files = {
        ".github/workflows/ci.yml": ci,
        ".github/workflows/security-triage.yml": render("security-triage.yml.tmpl", vals),
        ".github/workflows/scorecard.yml": render("scorecard.yml.tmpl", vals),
        ".github/CODEOWNERS": render("CODEOWNERS.tmpl", vals),
        ".github/pull_request_template.md": render("pull_request_template.md", vals),
        ".pre-commit-config.yaml": render("pre-commit-config.yaml", vals),
        ".security/exceptions.yaml": render("exceptions.yaml", vals),
    }
    if lang.get("dependabot"):
        files[".github/dependabot.yml"] = render(f"dependabot-{lang['dependabot']}.yml.tmpl", vals)
    return files


def onboard(gh: Gh, org: str, repo: dict, sha: str, version: str, team_ids: dict, skip_pr: bool = False) -> str:
    name = repo["name"]
    gh.call("PATCH", f"orgs/{org}/properties/values", {"repository_names": [name], "properties": [
        {"property_name": "paved-road", "value": "true"},
        {"property_name": "ring", "value": str(repo["ring"])},
        {"property_name": "risk-tier", "value": repo["risk_tier"]},
        {"property_name": "language", "value": repo["language"]},
        {"property_name": "owner-team", "value": repo["owner_team"]},
    ]})
    for team, perm in ((repo["owner_team"], "push"), ("appsec", "push"), ("platform", "push")):
        gh.call("PUT", f"orgs/{org}/teams/{team}/repos/{org}/{name}", {"permission": perm})
    envs = load_yaml(os.path.join(HERE, "..", "governance", "environments.json"))
    for env, cfg in envs.items():
        body = {"wait_timer": cfg.get("wait_timer", 0),
                "prevent_self_review": cfg.get("prevent_self_review", False),
                "reviewers": [{"type": "Team", "id": team_ids.get(t, 0)} for t in cfg.get("reviewer_teams", [])],
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False} if cfg.get("main_only") else None}
        gh.call("PUT", f"repos/{org}/{name}/environments/{env}", body)

    if skip_pr:
        return "properties, teams, environments applied; paved-road files ship with the first push"
    has_ci = None if gh.dry_run and not repo.get("real") else gh.get(f"repos/{org}/{name}/contents/.github/workflows/ci.yml", allow_404=True)
    if has_ci:
        return "properties, teams, environments applied; caller already present"
    files = files_for(repo, sha, version)
    if gh.dry_run:
        gh.log.append(f"DRY-RUN open onboarding PR on {org}/{name} with {len(files)} files: {', '.join(files)}")
        return f"would open onboarding PR ({len(files)} files)"
    base = gh.get(f"repos/{org}/{name}/git/ref/heads/main")["object"]["sha"]
    branch = f"paved-road/onboard-{version}"
    gh.call("POST", f"repos/{org}/{name}/git/refs", {"ref": f"refs/heads/{branch}", "sha": base}, ok_codes=("Reference already exists",))
    for path, content in files.items():
        existing = gh.get(f"repos/{org}/{name}/contents/{path}?ref={branch}", allow_404=True)
        body = {"message": f"paved-road: add {path}", "branch": branch, "content": base64.b64encode(content.encode()).decode()}
        if existing:
            body["sha"] = existing["sha"]
        gh.call("PUT", f"repos/{org}/{name}/contents/{path}", body)
    pr = gh.call("POST", f"repos/{org}/{name}/pulls", {
        "title": f"Onboard to the paved road ({version})", "head": branch, "base": "main",
        "body": "Adds the paved-road caller workflow and supporting files. All security controls run from "
                f"Triorex/paved-road-platform@{sha[:12]}. See the platform README for what each gate does."})
    return f"onboarding PR opened: {(pr or {}).get('html_url', '?')}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default=os.path.join(HERE, "inventory.yaml"))
    ap.add_argument("--platform-sha", required=True)
    ap.add_argument("--platform-version", required=True)
    ap.add_argument("--ring", type=int, choices=[0, 1, 2], help="only this rollout ring")
    ap.add_argument("--repo", help="only this repo")
    ap.add_argument("--apply", action="store_true", help="apply to repos marked real: true (others stay dry-run)")
    ap.add_argument("--skip-pr", action="store_true", help="settings only; the repo's first push already carries the paved-road files")
    args = ap.parse_args(argv)

    inv = load_yaml(args.inventory)
    org = inv["org"]
    repos = [r for r in inv["repos"] if (args.ring is None or r["ring"] == args.ring) and (not args.repo or r["name"] == args.repo)]
    live, plan = Gh(dry_run=False), Gh(dry_run=True)
    team_ids = {t["slug"]: t["id"] for t in (live.get(f"orgs/{org}/teams?per_page=100") or [])} if args.apply else {}

    rows, outcomes = [], Counter()
    for repo in repos:
        gh = live if (args.apply and repo.get("real")) else plan
        try:
            result = onboard(gh, org, repo, args.platform_sha, args.platform_version, team_ids, args.skip_pr)
            outcomes["applied" if gh is live else "planned"] += 1
        except GhError as exc:
            result = f"FAILED: {exc}"
            outcomes["failed"] += 1
        rows.append((repo["name"], repo["ring"], repo["language"], repo["risk_tier"], "live" if gh is live else "dry-run", result))

    print(f"# Fleet onboarding to {args.platform_version} ({args.platform_sha[:12]})\n")
    print(f"Repos: {len(rows)} · applied {outcomes['applied']} · planned {outcomes['planned']} · failed {outcomes['failed']}\n")
    print("| Repo | Ring | Language | Risk | Mode | Result |\n|---|---|---|---|---|---|")
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")
    if os.environ.get("VERBOSE"):
        print("\n```\n" + "\n".join(live.log + plan.log) + "\n```")
    return 1 if outcomes["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
