#!/usr/bin/env python3
"""Gate on SARIF results by level.

Every scanner uploads SARIF to the GitHub Security tab (one place to triage). This script turns
the same files into a pass/fail decision so the gate and the report never disagree.

Usage: sarif_gate.py --name SAST --mode enforce --fail-levels error semgrep.sarif bandit.sarif
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from prlib import finish, summary  # noqa: E402


def count_levels(paths: list[str]) -> tuple[Counter, list[dict]]:
    levels: Counter = Counter()
    findings: list[dict] = []
    for path in paths:
        if not os.path.exists(path):
            print(f"::warning::SARIF file not found: {path}")
            continue
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for run in doc.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []}
            for res in run.get("results", []) or []:
                rule = rules.get(res.get("ruleId"), {})
                level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
                levels[level] += 1
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                findings.append({
                    "tool": tool,
                    "rule": res.get("ruleId", "?"),
                    "level": level,
                    "file": loc.get("artifactLocation", {}).get("uri", "?"),
                    "line": loc.get("region", {}).get("startLine", "?"),
                })
    return levels, findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif", nargs="+")
    ap.add_argument("--name", required=True)
    ap.add_argument("--mode", default="enforce", choices=["enforce", "audit"])
    ap.add_argument("--fail-levels", nargs="+", default=["error"])
    args = ap.parse_args(argv)

    levels, findings = count_levels(args.sarif)
    blocking = [f for f in findings if f["level"] in args.fail_levels]
    lines = [f"### {args.name}", "", f"Mode: `{args.mode}` · blocking levels: `{', '.join(args.fail_levels)}`", ""]
    lines.append("| Level | Count |\n|---|---|")
    for level in ("error", "warning", "note", "none"):
        lines.append(f"| {level} | {levels.get(level, 0)} |")
    if blocking:
        # Counts and rule IDs only: Actions logs on public repos are world-readable, so file and line
        # stay in the permission-restricted Security tab (the SARIF is uploaded there).
        rules = Counter((f["tool"], f["rule"]) for f in blocking)
        lines += ["", "| Tool | Rule | Findings |", "|---|---|---|"]
        lines += [f"| {tool} | `{rule}` | {n} |" for (tool, rule), n in rules.most_common(50)]
    summary("\n".join(lines))
    return finish(args.name, args.mode, len(blocking))


if __name__ == "__main__":
    sys.exit(main())
