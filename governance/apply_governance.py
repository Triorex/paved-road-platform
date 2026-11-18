#!/usr/bin/env python3
"""Apply org-level governance as code to the Triorex organization.

Idempotent: safe to re-run. Dry-run by default; pass --apply to make changes.

  teams                 appsec, platform, payments-team, orders-team
  custom properties     paved-road, ring, risk-tier, language, owner-team
  security config       paved-road-baseline, enforced on every public repo and default for new public repos
  actions policy        selected actions only, SHA pinning required, read-only default token
  hardening             no member-created repos, read default, approval for every outside
                        contributor's workflow run, 7-day artifact and log retention
  OIDC subject claim    includes job_workflow_ref so cloud roles can trust only the central workflow
  org ruleset           default branch of every repo with paved-road=true: PR required,
                        "pr-security / gate" required, CodeQL high+ alerts block merge

With these at org level, onboarding repo #81 is: set its properties. The ruleset and the
security configuration then apply automatically.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fleet"))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from ghapi import Gh, GhError  # noqa: E402
from prlib import load_yaml  # noqa: E402


def spec(name: str):
    path = os.path.join(HERE, name)
    return load_yaml(path) if name.endswith(".yaml") else json.load(open(path, encoding="utf-8"))


def ensure_teams(gh: Gh, org: str) -> None:
    existing = {t["slug"] for t in gh.get(f"orgs/{org}/teams?per_page=100") or []}
    for team in spec("teams.yaml")["teams"]:
        if team["name"] not in existing:
            gh.call("POST", f"orgs/{org}/teams", {"name": team["name"], "description": team["description"], "privacy": "closed"})


def ensure_properties(gh: Gh, org: str) -> None:
    for prop in spec("custom-properties.json"):
        body = {k: v for k, v in prop.items() if k != "property_name"}
        gh.call("PUT", f"orgs/{org}/properties/schema/{prop['property_name']}", body)


def ensure_security_configuration(gh: Gh, org: str) -> None:
    cfg = spec("security-configuration.json")
    existing = {c["name"]: c for c in gh.get(f"orgs/{org}/code-security/configurations") or []}
    if cfg["name"] in existing:
        cid = existing[cfg["name"]]["id"]
        gh.call("PATCH", f"orgs/{org}/code-security/configurations/{cid}", cfg)
    else:
        created = gh.call("POST", f"orgs/{org}/code-security/configurations", cfg)
        cid = (created or {}).get("id", "<new-id>")
    gh.call("POST", f"orgs/{org}/code-security/configurations/{cid}/attach", {"scope": "public"})
    gh.call("PUT", f"orgs/{org}/code-security/configurations/{cid}/defaults", {"default_for_new_repos": "public"})


def ensure_actions_policy(gh: Gh, org: str) -> None:
    pol = spec("actions-policy.json")
    gh.call("PUT", f"orgs/{org}/actions/permissions", pol["permissions"])
    gh.call("PUT", f"orgs/{org}/actions/permissions/selected-actions", pol["selected_actions"])
    gh.call("PUT", f"orgs/{org}/actions/permissions/workflow", pol["workflow_permissions"])


def ensure_oidc_subject(gh: Gh, org: str) -> None:
    gh.call("PUT", f"orgs/{org}/actions/oidc/customization/sub", spec("oidc-subject.json"))


def ensure_org_hardening(gh: Gh, org: str) -> None:
    hard = spec("org-hardening.json")
    gh.call("PATCH", f"orgs/{org}", hard["org"])
    gh.call("PUT", f"orgs/{org}/actions/permissions/fork-pr-contributor-approval", hard["fork_pr_contributor_approval"])
    gh.call("PUT", f"orgs/{org}/actions/permissions/artifact-and-log-retention", hard["artifact_and_log_retention"])


def ensure_ruleset(gh: Gh, org: str) -> None:
    rs = spec("org-ruleset.json")
    existing = {r["name"]: r["id"] for r in gh.get(f"orgs/{org}/rulesets") or []}
    if rs["name"] in existing:
        gh.call("PUT", f"orgs/{org}/rulesets/{existing[rs['name']]}", rs)
    else:
        gh.call("POST", f"orgs/{org}/rulesets", rs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", default="Triorex")
    ap.add_argument("--apply", action="store_true", help="make changes (default: dry run)")
    ap.add_argument("--only", nargs="*", choices=["hardening", "teams", "properties", "security", "actions", "oidc", "ruleset"])
    args = ap.parse_args(argv)

    gh = Gh(dry_run=not args.apply)
    steps = [("hardening", ensure_org_hardening), ("teams", ensure_teams), ("properties", ensure_properties), ("security", ensure_security_configuration),
             ("actions", ensure_actions_policy), ("oidc", ensure_oidc_subject), ("ruleset", ensure_ruleset)]
    failed = []
    for name, fn in steps:
        if args.only and name not in args.only:
            continue
        try:
            fn(gh, args.org)
            print(f"[ok]   {name}")
        except GhError as exc:
            failed.append(name)
            print(f"[fail] {name}: {exc}")
    print("\n".join(gh.log))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
