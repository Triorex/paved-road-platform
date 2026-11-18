#!/usr/bin/env python3
"""Risk-based vulnerability triage: turn scanner alerts into owned, SLA-tracked issues.

1. Pull open code-scanning alerts (CodeQL, Semgrep, Trivy, OSV, Checkov... all land there as SARIF)
   and, when a token with access is provided, Dependabot alerts.
2. Enrich every CVE with CISA KEV (exploited in the wild) and FIRST EPSS (exploit probability).
3. Prioritise:  KEV -> P0 (zero-day SLA) | critical or EPSS >= 0.5 -> P1 | high or EPSS >= 0.1 -> P2
                | medium -> P3 | low -> P4
4. Open one GitHub Issue per alert with priority label, SLA due date and owner; update it when the
   priority changes; close it when a rescan no longer reports the alert. Closure is therefore
   verified by the scanner, not by someone ticking a box.

At fleet scale this runs as a GitHub App across all repos; in the demo each repo runs it on a
schedule with its own GITHUB_TOKEN.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from prlib import http_json, load_yaml, summary  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
LABEL = "paved-road-triage"
PRIORITY_SLA = {"P0": "zero_day", "P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}


class GitHub:
    def __init__(self, repo: str, token: str, api: str = "https://api.github.com"):
        self.repo, self.api = repo, api.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def get_all(self, path: str) -> list[dict]:
        out, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            batch = http_json(f"{self.api}/repos/{self.repo}/{path}{sep}per_page=100&page={page}", headers=self.headers)
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    def call(self, method: str, path: str, data: dict) -> dict:
        import json
        import urllib.request
        req = urllib.request.Request(f"{self.api}/repos/{self.repo}/{path}", data=json.dumps(data).encode(),
                                     headers={**self.headers, "Content-Type": "application/json"}, method=method)
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310 -- fixed https API hosts only; nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            body = resp.read()
            return json.loads(body) if body else {}


def priority(severity: str, kev: bool, epss: float | None) -> str:
    sev = (severity or "").lower()
    e = epss or 0.0
    if kev:
        return "P0"
    if sev == "critical" or e >= 0.5:
        return "P1"
    if sev in ("high", "error") or e >= 0.1:
        return "P2"
    if sev in ("medium", "warning"):
        return "P3"
    return "P4"


def collect_alerts(gh: GitHub, dependabot: GitHub | None) -> list[dict]:
    alerts = []
    for a in gh.get_all("code-scanning/alerts?state=open"):
        rule = a.get("rule", {})
        text = " ".join(str(rule.get(k, "")) for k in ("id", "name", "description"))
        alerts.append({
            "key": f"code-scanning:{a['number']}",
            "source": a.get("tool", {}).get("name", "scanner"),
            "title": rule.get("description") or rule.get("id"),
            "severity": rule.get("security_severity_level") or rule.get("severity") or "",
            "cves": sorted(set(CVE_RE.findall(text))),
            "location": a.get("most_recent_instance", {}).get("location", {}).get("path", ""),
            "url": a.get("html_url", ""),
        })
    if dependabot:
        for a in dependabot.get_all("dependabot/alerts?state=open"):
            adv = a.get("security_advisory", {})
            alerts.append({
                "key": f"dependabot:{a['number']}",
                "source": "Dependabot",
                "title": adv.get("summary", ""),
                "severity": adv.get("severity", ""),
                "cves": [adv["cve_id"]] if adv.get("cve_id") else [],
                "location": a.get("dependency", {}).get("manifest_path", ""),
                "url": a.get("html_url", ""),
            })
    return alerts


def enrich(alerts: list[dict]) -> None:
    cves = sorted({c for a in alerts for c in a["cves"]})
    kev: set[str] = set()
    epss: dict[str, float] = {}
    if cves:
        try:
            kev = {v["cveID"] for v in http_json(KEV_URL).get("vulnerabilities", [])}
        except Exception as exc:
            print(f"::warning::CISA KEV feed unavailable ({exc}); KEV escalation skipped this run")
        for i in range(0, len(cves), 100):
            try:
                for row in http_json(EPSS_URL + ",".join(cves[i:i + 100])).get("data", []):
                    epss[row["cve"]] = float(row["epss"])
            except Exception as exc:
                print(f"::warning::EPSS API unavailable ({exc})")
    for a in alerts:
        a["kev"] = any(c in kev for c in a["cves"])
        a["epss"] = max((epss.get(c, 0.0) for c in a["cves"]), default=None) if a["cves"] else None
        a["priority"] = priority(a["severity"], a["kev"], a["epss"])


def codeowner(root: str) -> str:
    for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        full = os.path.join(root, path)
        if os.path.exists(full):
            for line in open(full, encoding="utf-8"):
                parts = line.split("#", 1)[0].split()
                if parts and parts[0] == "*" and len(parts) > 1:
                    return parts[1]
    return "@Triorex/appsec"


def sync_issues(gh: GitHub, alerts: list[dict], sla_days: dict, owner: str, today: dt.date) -> dict:
    for name, color in [(LABEL, "5319e7"), ("security", "b60205")] + [(f"priority:{p}", "d93f0b") for p in PRIORITY_SLA]:
        try:
            gh.call("POST", "labels", {"name": name, "color": color})
        except Exception:
            pass  # already exists
    existing = {}
    for issue in gh.get_all(f"issues?state=open&labels={LABEL}"):
        m = re.search(r"<!-- triage-key: (\S+) -->", issue.get("body") or "")
        if m:
            existing[m.group(1)] = issue
    stats = {"opened": 0, "updated": 0, "closed": 0}
    live_keys = set()
    for a in alerts:
        live_keys.add(a["key"])
        due = today + dt.timedelta(days=int(sla_days.get(PRIORITY_SLA[a["priority"]], 90)))
        cve = ", ".join(a["cves"]) or "n/a"
        title = f"[{a['priority']}] {a['source']}: {a['title'][:90]}"
        body = (f"<!-- triage-key: {a['key']} -->\n**Priority:** {a['priority']} · **SLA due:** {due} · **Owner:** {owner}\n\n"
                f"| Field | Value |\n|---|---|\n| Source | {a['source']} |\n| Severity | {a['severity'] or 'n/a'} |\n"
                f"| CVE | {cve} |\n| CISA KEV | {'**yes**' if a['kev'] else 'no'} |\n"
                f"| EPSS | {a['epss'] if a['epss'] is not None else 'n/a'} |\n| Location | `{a['location']}` |\n"
                f"| Alert | {a['url']} |\n\nThis issue closes automatically when a rescan no longer reports the alert. "
                f"If it cannot be fixed by the due date, file a time-boxed exception in `.security/exceptions.yaml`.")
        labels = [LABEL, "security", f"priority:{a['priority']}"]
        if a["key"] in existing:
            issue = existing[a["key"]]
            if issue["title"] != title:
                gh.call("PATCH", f"issues/{issue['number']}", {"title": title, "labels": labels})
                stats["updated"] += 1
        else:
            gh.call("POST", "issues", {"title": title, "body": body, "labels": labels})
            stats["opened"] += 1
    for key, issue in existing.items():
        if key not in live_keys:
            gh.call("POST", f"issues/{issue['number']}/comments", {"body": "Rescan no longer reports this alert. Closing as fixed."})
            gh.call("PATCH", f"issues/{issue['number']}", {"state": "closed", "state_reason": "completed"})
            stats["closed"] += 1
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")
    if not repo or not token:
        print("::error::GITHUB_REPOSITORY and GITHUB_TOKEN are required")
        return 2
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    gh = GitHub(repo, token, api)
    dep_token = os.environ.get("DEPENDABOT_ALERTS_TOKEN")
    alerts = collect_alerts(gh, GitHub(repo, dep_token, api) if dep_token else None)
    enrich(alerts)
    alerts.sort(key=lambda a: (a["priority"], -(a["epss"] or 0)))

    sla_days = load_yaml(args.policy).get("sla_days", {})
    stats = {"opened": 0, "updated": 0, "closed": 0}
    if not args.dry_run:
        stats = sync_issues(gh, alerts, sla_days, codeowner(args.root), dt.date.today())

    lines = ["### Vulnerability triage", "",
             f"Open alerts: **{len(alerts)}** · issues opened {stats['opened']}, updated {stats['updated']}, "
             f"closed after rescan {stats['closed']}{' (dry run)' if args.dry_run else ''}", ""]
    if alerts:
        lines += ["| Priority | Source | CVE | KEV | EPSS | Finding |", "|---|---|---|---|---|---|"]
        for a in alerts[:60]:
            lines.append(f"| {a['priority']} | {a['source']} | {', '.join(a['cves']) or '–'} | "
                         f"{'yes' if a['kev'] else ''} | {a['epss'] if a['epss'] is not None else ''} | {a['title'][:70]} |")
    summary("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
