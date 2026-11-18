#!/usr/bin/env python3
"""Package curation gate: the open-source "front door" check, without an artifact manager.

For every pinned dependency in requirements*.txt (PyPI) and package-lock.json (npm) it checks:
  1. Known-malicious   OSV advisories with a MAL- id (OpenSSF malicious-packages feed)  -> block
  2. Release age       versions younger than min_release_age_days                      -> block
                       (most malicious releases are caught and pulled within days, e.g. the
                       2025 npm "Shai-Hulud" worm; a cooldown keeps them out)
  3. License           SPDX license outside the allowlist                               -> block
                       unknown license                                                  -> warn

In the enterprise design JFrog Curation does this at download time for every developer and
build; this script is the same policy run in CI, so the demo enforces it without a JFrog tenant.
Approved packages can be exempted with a `type: package` exception (name==version).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import glob
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))
from prlib import finish, http_json, load_yaml, summary  # noqa: E402

OSV_BATCH = "https://api.osv.dev/v1/querybatch"

CLASSIFIER_SPDX = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "ISC License (ISCL)": "ISC",
    "Python Software Foundation License": "PSF-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
}
LICENSE_ALIASES = {
    "mit": "MIT", "mit license": "MIT", "apache 2.0": "Apache-2.0", "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache software license": "Apache-2.0", "bsd": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause", "bsd-2-clause": "BSD-2-Clause", "isc": "ISC", "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0", "mpl-2.0": "MPL-2.0", "0bsd": "0BSD", "unlicense": "Unlicense",
    "blueoak-1.0.0": "BlueOak-1.0.0", "cc0-1.0": "CC0-1.0",
}


# ---------------------------------------------------------------- parsing
def parse_requirements(path: str) -> list[tuple[str, str, str]]:
    pkgs: list[tuple[str, str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip().rstrip("\\").strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?==([A-Za-z0-9_.\-+!]+)", line)
            if m:
                pkgs.append(("PyPI", re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(3)))
    return pkgs


def parse_package_lock(path: str) -> list[tuple[str, str, str]]:
    with open(path, encoding="utf-8") as fh:
        lock = json.load(fh)
    pkgs = set()
    for key, meta in (lock.get("packages") or {}).items():
        if not key or "node_modules/" not in key or meta.get("link"):
            continue
        name = key.rsplit("node_modules/", 1)[1]
        if meta.get("version"):
            pkgs.add(("npm", name, meta["version"]))
    return sorted(pkgs)


def discover(root: str) -> list[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for path in glob.glob(os.path.join(root, "**", "requirements*.txt"), recursive=True):
        if "/.platform/" in path or "/node_modules/" in path:
            continue
        found.update(parse_requirements(path))
    for path in glob.glob(os.path.join(root, "**", "package-lock.json"), recursive=True):
        if "/node_modules/" in path or "/.platform/" in path:
            continue
        found.update(parse_package_lock(path))
    return sorted(found)


# ---------------------------------------------------------------- lookups
def normalise_license(raw: str | None) -> str:
    if not raw:
        return "UNKNOWN"
    raw = raw.strip()
    if len(raw) > 80:  # full license text pasted into metadata
        return "UNKNOWN"
    return LICENSE_ALIASES.get(raw.lower(), raw)


def pypi_meta(name: str, version: str) -> dict:
    doc = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
    info = doc.get("info", {})
    times = [u["upload_time_iso_8601"] for u in doc.get("urls", []) if u.get("upload_time_iso_8601")]
    lic = info.get("license_expression") or ""
    if not lic:
        for c in info.get("classifiers") or []:
            if c.startswith("License :: OSI Approved :: "):
                lic = CLASSIFIER_SPDX.get(c.rsplit(":: ", 1)[1], c.rsplit(":: ", 1)[1])
                break
    if not lic:
        lic = info.get("license") or ""
    return {"published": min(times) if times else None, "license": normalise_license(lic)}


def npm_meta(name: str, version: str) -> dict:
    doc = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    ver = (doc.get("versions") or {}).get(version, {})
    lic = ver.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    return {"published": (doc.get("time") or {}).get(version), "license": normalise_license(lic)}


def malicious_ids(pkgs: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
    out: dict[tuple[str, str, str], list[str]] = {}
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
        res = http_json(OSV_BATCH, data={"queries": queries})
        for pkg, r in zip(chunk, res.get("results", [])):
            mal = [v["id"] for v in r.get("vulns", []) or [] if v.get("id", "").startswith("MAL-")]
            if mal:
                out[pkg] = mal
    return out


# ---------------------------------------------------------------- evaluation
def evaluate(pkgs, metas, malicious, policy, exempt, now):
    min_age = int(((policy.get("gates") or {}).get("curation") or {}).get("min_release_age_days", 7))
    allow = set((policy.get("licenses") or {}).get("allow") or [])
    rows = []
    for pkg in pkgs:
        eco, name, ver = pkg
        meta = metas.get(pkg, {})
        problems, warnings = [], []
        if pkg in malicious:
            problems.append(f"malicious ({', '.join(malicious[pkg])})")
        pub = meta.get("published")
        if pub:
            age = (now - dt.datetime.fromisoformat(pub.replace("Z", "+00:00"))).days
            if age < min_age:
                problems.append(f"released {age}d ago (< {min_age}d cooldown)")
        else:
            warnings.append("publish date unknown")
        lic = meta.get("license", "UNKNOWN")
        if lic == "UNKNOWN":
            warnings.append("license unknown")
        elif not any(part.strip("() ") in allow for part in re.split(r"\s+OR\s+", lic)):
            problems.append(f"license {lic} not in allowlist")
        if meta.get("error"):
            warnings.append(f"lookup failed: {meta['error']}")
        if f"{name}=={ver}" in exempt and problems:
            warnings.append(f"exempted ({exempt[f'{name}=={ver}']}): {'; '.join(problems)}")
            problems = []
        rows.append({"eco": eco, "name": name, "version": ver, "license": lic, "problems": problems, "warnings": warnings})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--exceptions", default=".security/exceptions.yaml")
    args = ap.parse_args(argv)

    policy = load_yaml(args.policy)
    mode = ((policy.get("gates") or {}).get("curation") or {}).get("mode", "enforce")
    exc_doc = load_yaml(args.exceptions) if os.path.exists(args.exceptions) else {}
    exempt = {e["target"]: e["id"] for e in exc_doc.get("exceptions") or [] if e.get("type") == "package"}

    pkgs = discover(args.root)
    if not pkgs:
        summary("### Package curation\n\nNo pinned dependencies found.")
        return 0

    def fetch(pkg):
        eco, name, ver = pkg
        try:
            return pkg, (pypi_meta(name, ver) if eco == "PyPI" else npm_meta(name, ver))
        except Exception as exc:  # network or 404: report, never silently pass a malicious check
            return pkg, {"error": type(exc).__name__}

    with cf.ThreadPoolExecutor(max_workers=12) as pool:
        metas = dict(pool.map(fetch, pkgs))
    malicious = malicious_ids(pkgs)
    rows = evaluate(pkgs, metas, malicious, policy, exempt, dt.datetime.now(dt.timezone.utc))

    blocked = [r for r in rows if r["problems"]]
    warned = [r for r in rows if r["warnings"] and not r["problems"]]
    lines = ["### Package curation", "",
             f"Checked **{len(rows)}** packages · blocked **{len(blocked)}** · warnings **{len(warned)}** · mode `{mode}`", ""]
    if blocked or warned:
        lines += ["| Package | Version | License | Result |", "|---|---|---|---|"]
        for r in blocked + warned:
            result = "BLOCK: " + "; ".join(r["problems"]) if r["problems"] else "warn: " + "; ".join(r["warnings"])
            lines.append(f"| {r['eco']}:{r['name']} | {r['version']} | {r['license']} | {result} |")
    summary("\n".join(lines))
    for r in blocked:
        print(f"::error::curation: {r['eco']}:{r['name']}@{r['version']}: {'; '.join(r['problems'])}")
    return finish("curation", mode, len(blocked))


if __name__ == "__main__":
    sys.exit(main())
