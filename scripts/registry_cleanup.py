#!/usr/bin/env python3
"""Registry hygiene: delete container images that never reached an environment.

Every build pushes an image (tag sha-<commit>) plus its signature (.sig), cosign attestation
(.att) and GitHub attestation referrer (sha256-<digest>). Most builds are never promoted. This
keeps the registry to what matters:

  KEEP   images tagged staging or production (and anything they reference)
  KEEP   the newest --keep-last sha-* images (rollback candidates and recent builds)
  KEEP   anything younger than --min-age-days, and every untagged version (it may be referenced)
  DELETE older, unpromoted sha-* images together with their .sig / .att / referrer companions

Dry run by default. Deleting needs a token with admin rights on the package.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from prlib import http_json, summary  # noqa: E402

BUILD_TAG = re.compile(r"^sha-[0-9a-f]{40}$")
COMPANION = re.compile(r"^sha256-([0-9a-f]{64})(\.sig|\.att)?$")
PROMOTED = {"staging", "production"}


def plan(versions: list[dict], keep_last: int, min_age_days: int, now: dt.datetime) -> tuple[list[dict], list[dict]]:
    """Return (keep, delete) lists of package versions."""
    def tags(v):
        return set(((v.get("metadata") or {}).get("container") or {}).get("tags") or [])

    def age_days(v):
        return (now - dt.datetime.fromisoformat(v["created_at"].replace("Z", "+00:00"))).days

    images = sorted((v for v in versions if any(BUILD_TAG.match(t) for t in tags(v)) or tags(v) & PROMOTED),
                    key=lambda v: v["created_at"], reverse=True)
    keep_digests = set()
    for i, v in enumerate(images):
        if tags(v) & PROMOTED or i < keep_last or age_days(v) < min_age_days:
            keep_digests.add(v["name"])
    delete_digests = {v["name"] for v in images} - keep_digests

    keep, delete = [], []
    for v in versions:
        t = tags(v)
        if v["name"] in delete_digests:
            delete.append(v)
            continue
        companion_of = {m.group(1) for m in (COMPANION.match(x) for x in t) if m}
        if companion_of and all(f"sha256:{h}" in delete_digests for h in companion_of):
            delete.append(v)
            continue
        keep.append(v)
    return keep, delete


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--keep-last", type=int, default=10)
    ap.add_argument("--min-age-days", type=int, default=7)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    token = os.environ["GITHUB_TOKEN"]
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    base = f"https://api.github.com/orgs/{args.org}/packages/container/{args.package}/versions"
    versions, page = [], 1
    while True:
        batch = http_json(f"{base}?per_page=100&page={page}", headers=hdrs)
        versions += batch
        if len(batch) < 100:
            break
        page += 1

    keep, delete = plan(versions, args.keep_last, args.min_age_days, dt.datetime.now(dt.timezone.utc))
    deleted, failed = 0, 0
    if args.apply:
        for v in delete:
            try:
                http_json(f"{base}/{v['id']}", headers=hdrs, method="DELETE")
                deleted += 1
            except Exception as exc:  # report and continue; never abort half-way silently
                failed += 1
                print(f"::warning::could not delete version {v['id']} ({v['name'][:19]}): {exc}")
    mode = "apply" if args.apply else "dry run"
    lines = [f"### Registry cleanup: `{args.package}` ({mode})", "",
             f"Versions: **{len(versions)}** · keep **{len(keep)}** · delete **{len(delete)}**"
             + (f" · deleted {deleted} · failed {failed}" if args.apply else ""), ""]
    if delete:
        lines += ["| Version | Tags | Created |", "|---|---|---|"]
        for v in delete[:50]:
            t = ", ".join(((v.get("metadata") or {}).get("container") or {}).get("tags") or []) or "(untagged)"
            lines.append(f"| `{v['name'][:19]}` | {t[:60]} | {v['created_at'][:10]} |")
    summary("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
