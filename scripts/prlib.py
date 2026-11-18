"""Small shared helpers for paved-road scripts. Standard library + PyYAML only."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "triorex-paved-road/1.0 (+https://github.com/Triorex/paved-road-platform)"


def load_yaml(path: str) -> Any:
    import yaml  # imported lazily so scripts that never read YAML have no third-party dependency

    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def http_json(url: str, *, data: Any = None, headers: dict | None = None, timeout: int = 20) -> Any:
    """GET (or POST when data is given) a JSON document."""
    body = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 -- fixed https API hosts only; nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.load(resp)


def gate_mode(policy: dict, gate: str) -> str:
    return ((policy.get("gates") or {}).get(gate) or {}).get("mode", "enforce")


def summary(markdown: str) -> None:
    """Append to the GitHub job summary when running in Actions; print otherwise."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    else:
        print(markdown)


def finish(gate: str, mode: str, failures: int) -> int:
    """Return the process exit code for a gate, honouring audit mode."""
    if failures and mode == "enforce":
        print(f"::error::{gate}: {failures} blocking finding(s) (mode=enforce)")
        return 1
    if failures:
        print(f"::warning::{gate}: {failures} finding(s) reported only (mode=audit)")
    return 0


def die(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(2)


HTTPError = urllib.error.HTTPError
