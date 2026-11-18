#!/usr/bin/env python3
"""Validate a repo's risk exceptions and fail when any has expired.

Each app repo keeps `.security/exceptions.yaml`. CODEOWNERS routes changes to that file to the
AppSec team, so an exception is a reviewed, time-boxed decision rather than a silent ignore.

Valid exceptions for CVEs are also written out as a .trivyignore file, so Trivy honours exactly
the exceptions AppSec approved and nothing else.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from prlib import finish, load_yaml, summary  # noqa: E402

REQUIRED = ("id", "type", "target", "reason", "compensating_controls", "owner", "approved_by", "expires")
TYPES = {"cve", "package", "rule"}


def validate(doc: dict, today: dt.date, max_days: int) -> tuple[list[dict], list[str]]:
    valid: list[dict] = []
    problems: list[str] = []
    for i, exc in enumerate(doc.get("exceptions") or []):
        label = exc.get("id", f"#{i + 1}")
        missing = [k for k in REQUIRED if not exc.get(k)]
        if missing:
            problems.append(f"{label}: missing {', '.join(missing)}")
            continue
        if exc["type"] not in TYPES:
            problems.append(f"{label}: type must be one of {sorted(TYPES)}")
            continue
        try:
            expires = dt.date.fromisoformat(str(exc["expires"]))
        except ValueError:
            problems.append(f"{label}: expires must be YYYY-MM-DD")
            continue
        if expires < today:
            problems.append(f"{label}: EXPIRED on {expires} ({exc['target']}). Fix the finding or renew with AppSec approval.")
            continue
        if (expires - today).days > max_days:
            problems.append(f"{label}: expiry {expires} is more than {max_days} days out; exceptions must be time-boxed.")
            continue
        valid.append(exc)
    return valid, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=".security/exceptions.yaml")
    ap.add_argument("--max-days", type=int, default=90)
    ap.add_argument("--mode", default="enforce", choices=["enforce", "audit"])
    ap.add_argument("--today", default=None, help="YYYY-MM-DD (for tests)")
    ap.add_argument("--emit-trivyignore", default=None)
    args = ap.parse_args(argv)

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    doc = load_yaml(args.file) if os.path.exists(args.file) else {}
    valid, problems = validate(doc, today, args.max_days)

    if args.emit_trivyignore:
        with open(args.emit_trivyignore, "w", encoding="utf-8") as fh:
            for exc in valid:
                if exc["type"] == "cve":
                    fh.write(f"# {exc['id']} expires {exc['expires']} owner {exc['owner']}\n{exc['target']}\n")

    lines = ["### Risk exceptions", "", f"Active: **{len(valid)}** · problems: **{len(problems)}**", ""]
    if valid:
        lines += ["| ID | Type | Target | Expires | Owner |", "|---|---|---|---|---|"]
        lines += [f"| {e['id']} | {e['type']} | `{e['target']}` | {e['expires']} | {e['owner']} |" for e in valid]
    if problems:
        lines += ["", *[f"- {p}" for p in problems]]
    summary("\n".join(lines))
    return finish("exceptions", args.mode, len(problems))


if __name__ == "__main__":
    sys.exit(main())
