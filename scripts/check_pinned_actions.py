#!/usr/bin/env python3
"""Fail if any workflow or composite action references an action by a mutable ref.

Allowed:  owner/repo[/path]@<40-hex commit SHA>, ./local/path, docker://image@sha256:<digest>
Blocked:  @v4, @main, @latest, docker://image:tag

Mutable tags are how the March 2025 tj-actions/changed-files compromise spread: the attacker
moved existing tags to a malicious commit. A commit SHA cannot be moved.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from prlib import finish, summary  # noqa: E402

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOCKER_PINNED = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def scan(root: str) -> list[tuple[str, int, str]]:
    patterns = [".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/**/action.yml", "**/action.yml"]
    files = sorted({f for p in patterns for f in glob.glob(os.path.join(root, p), recursive=True)})
    bad: list[tuple[str, int, str]] = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                m = USES.match(line)
                if not m:
                    continue
                ref = m.group(1)
                if ref.startswith("./") or PINNED.match(ref) or DOCKER_PINNED.match(ref):
                    continue
                bad.append((os.path.relpath(path, root), n, ref))
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--mode", default="enforce", choices=["enforce", "audit"])
    args = ap.parse_args(argv)
    bad = scan(args.root)
    lines = ["### Action pinning", "", f"Unpinned references: **{len(bad)}**"]
    if bad:
        lines += ["", "| File | Line | Reference |", "|---|---|---|"]
        lines += [f"| `{f}` | {n} | `{r}` |" for f, n, r in bad]
        for f, n, r in bad:
            print(f"::error file={f},line={n}::'{r}' is not pinned to a full commit SHA")
    summary("\n".join(lines))
    return finish("action-pinning", args.mode, len(bad))


if __name__ == "__main__":
    sys.exit(main())
