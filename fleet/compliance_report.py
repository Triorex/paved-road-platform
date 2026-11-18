#!/usr/bin/env python3
"""Fleet compliance and adoption report: the paved-road KPI for leadership.

For each repo in the inventory it checks, live against GitHub:
  - onboarded           custom property paved-road=true
  - caller present      .github/workflows/ci.yml calls the platform's pr-security workflow
  - platform version    pinned SHA matches the latest platform release (or how far behind)
  - ruleset active      org ruleset rules apply to the default branch
  - baseline attached   paved-road-baseline security configuration is attached
  - push protection     secret scanning push protection is on
Simulated repos (real: false) are reported as planned, by rollout ring.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from ghapi import Gh, GhError  # noqa: E402
from prlib import load_yaml  # noqa: E402

PIN = re.compile(r"paved-road-platform/\.github/workflows/pr-security\.yml@([0-9a-f]{40})")


def check(gh: Gh, org: str, name: str, latest_sha: str | None) -> dict:
    out = {}
    repo = gh.get(f"repos/{org}/{name}", allow_404=True)
    if not repo:
        return {"exists": False}
    props = {p["property_name"]: p["value"] for p in gh.get(f"repos/{org}/{name}/properties/values") or []}
    out["onboarded"] = props.get("paved-road") == "true"
    ci = gh.get(f"repos/{org}/{name}/contents/.github/workflows/ci.yml", allow_404=True)
    pin = PIN.search(base64.b64decode(ci["content"]).decode()) if ci else None
    out["caller"] = bool(pin)
    out["pinned"] = pin.group(1) if pin else None
    out["current"] = bool(pin and latest_sha and pin.group(1) == latest_sha)
    rules = gh.get(f"repos/{org}/{name}/rules/branches/{repo['default_branch']}") or []
    types = {r["type"] for r in rules}
    out["ruleset"] = {"pull_request", "required_status_checks"} <= types
    cfg = gh.get(f"repos/{org}/{name}/code-security-configuration", allow_404=True)
    out["baseline"] = bool(cfg and (cfg.get("configuration") or {}).get("name") == "paved-road-baseline")
    sa = repo.get("security_and_analysis") or {}
    out["push_protection"] = (sa.get("secret_scanning_push_protection") or {}).get("status") == "enabled"
    out["exists"] = True
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default=os.path.join(HERE, "inventory.yaml"))
    ap.add_argument("--output", help="write markdown here as well as stdout")
    args = ap.parse_args(argv)

    inv = load_yaml(args.inventory)
    org = inv["org"]
    gh = Gh(dry_run=True)  # read-only
    try:
        rel = gh.get(f"repos/{inv['platform_repo']}/releases/latest", allow_404=True)
        latest_tag = rel["tag_name"] if rel else None
        latest_sha = gh.get(f"repos/{inv['platform_repo']}/commits/{latest_tag}")["sha"] if latest_tag else None
    except GhError:
        latest_tag = latest_sha = None

    cols = ["onboarded", "caller", "current", "ruleset", "baseline", "push_protection"]
    lines = [f"# Paved Road fleet report: {org}", "",
             f"Latest platform release: **{latest_tag or 'none'}**" + (f" (`{latest_sha[:12]}`)" if latest_sha else ""), "",
             "| Repo | Ring | Risk | " + " | ".join(c.replace('_', ' ') for c in cols) + " | Status |",
             "|---|---|---|" + "---|" * len(cols) + "---|"]
    status = Counter()
    by_ring: dict[int, Counter] = {}
    for repo in inv["repos"]:
        ring_c = by_ring.setdefault(repo["ring"], Counter())
        ring_c["total"] += 1
        if not repo.get("real"):
            status["planned"] += 1
            continue
        try:
            res = check(gh, org, repo["name"], latest_sha)
        except GhError as exc:
            res = {"exists": True, "error": str(exc)[:80]}
        ok = res.get("exists") and all(res.get(c) for c in cols)
        state = "compliant" if ok else ("missing" if not res.get("exists") else "drift")
        status[state] += 1
        ring_c[state] += 1
        marks = " | ".join("✅" if res.get(c) else "❌" for c in cols)
        lines.append(f"| {repo['name']} | {repo['ring']} | {repo['risk_tier']} | {marks} | {state} |")

    total = len(inv["repos"])
    lines += ["", f"**Adoption:** {status['compliant']} of {total} repos fully on the paved road "
              f"({100 * status['compliant'] // total}%) · drift {status['drift']} · not yet onboarded {status['planned'] + status['missing']}", "",
              "| Ring | Repos | Compliant |", "|---|---|---|"]
    for ring in sorted(by_ring):
        c = by_ring[ring]
        lines.append(f"| {ring} | {c['total']} | {c['compliant']} |")
    text = "\n".join(lines)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
