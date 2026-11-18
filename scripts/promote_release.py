#!/usr/bin/env python3
"""Gate a platform release candidate on ring-0 production evidence.

A platform release is cut first as a candidate (vX.Y.Z-rc.N, a GitHub pre-release) and pinned
only by ring-0 repositories. It may be promoted to the final vX.Y.Z (same commit) only when:

  1. platform-ci succeeded on the candidate commit, and
  2. every ring-0 repository that exists has a successful PRODUCTION deployment whose
     .github/workflows/ci.yml pins the candidate commit.

Ring-0 repos listed in the inventory but not created yet are reported and skipped; at least one
must provide evidence. Prints a markdown evidence table; exit 0 means the candidate may be promoted.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(__file__))
from prlib import http_json, load_yaml, summary  # noqa: E402

API = "https://api.github.com"


def evaluate(platform_ci_ok: bool, ring0: list[dict]) -> tuple[bool, list[str]]:
    """ring0 items: {name, exists, deployments: [{pins_rc: bool, success: bool}]}"""
    reasons = []
    if not platform_ci_ok:
        reasons.append("platform-ci has not succeeded on the candidate commit")
    existing = [r for r in ring0 if r["exists"]]
    if not existing:
        reasons.append("no ring-0 repository exists to provide production evidence")
    for r in existing:
        if not any(d["pins_rc"] and d["success"] for d in r["deployments"]):
            reasons.append(f"{r['name']}: no successful production deployment pinned to the candidate")
    return (not reasons), reasons


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rc-tag", required=True)
    ap.add_argument("--inventory", default=os.path.join(os.path.dirname(__file__), "..", "fleet", "inventory.yaml"))
    args = ap.parse_args(argv)
    if not re.fullmatch(r"v\d+\.\d+\.\d+-rc\.\d+", args.rc_tag):
        print(f"::error::{args.rc_tag} is not a release candidate tag (vX.Y.Z-rc.N)")
        return 2

    hdrs = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json"}
    inv = load_yaml(args.inventory)
    org, platform = inv["org"], inv["platform_repo"]
    rc_sha = http_json(f"{API}/repos/{platform}/commits/{args.rc_tag}", headers=hdrs)["sha"]

    runs = http_json(f"{API}/repos/{platform}/actions/runs?head_sha={rc_sha}&per_page=50", headers=hdrs).get("workflow_runs", [])
    platform_ci_ok = any(r["name"] == "platform-ci" and r["conclusion"] == "success" for r in runs)

    ring0 = []
    for repo in (r for r in inv["repos"] if r["ring"] == 0):
        name = repo["name"]
        entry = {"name": name, "exists": True, "deployments": []}
        try:
            deps = http_json(f"{API}/repos/{org}/{name}/deployments?environment=production&per_page=20", headers=hdrs)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                entry["exists"] = False
                ring0.append(entry)
                continue
            raise
        for d in deps:
            try:
                ci = http_json(f"{API}/repos/{org}/{name}/contents/.github/workflows/ci.yml?ref={d['sha']}", headers=hdrs)
                pins = rc_sha in base64.b64decode(ci["content"]).decode()
            except urllib.error.HTTPError:
                pins = False
            statuses = http_json(d["statuses_url"], headers=hdrs)
            success = bool(statuses) and statuses[0]["state"] == "success"
            entry["deployments"].append({"sha": d["sha"][:7], "pins_rc": pins, "success": success})
        ring0.append(entry)

    ok, reasons = evaluate(platform_ci_ok, ring0)
    lines = [f"### Release candidate `{args.rc_tag}` (`{rc_sha[:12]}`)", "",
             f"- platform-ci on the candidate commit: {'✅' if platform_ci_ok else '❌'}", "",
             "| Ring-0 repo | Production deployment pinned to the candidate |", "|---|---|"]
    for r in ring0:
        if not r["exists"]:
            lines.append(f"| {r['name']} | not created yet (skipped) |")
            continue
        hits = [d for d in r["deployments"] if d["pins_rc"] and d["success"]]
        lines.append(f"| {r['name']} | {'✅ ' + ', '.join(d['sha'] for d in hits) if hits else '❌ none'} |")
    lines += ["", f"**Decision: {'PROMOTE' if ok else 'BLOCKED'}**"] + [f"- {x}" for x in reasons]
    text = "\n".join(lines)
    summary(text)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"rc_sha={rc_sha}\n")
    with open("rc-evidence.md", "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
