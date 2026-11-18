"""Thin wrapper over the `gh api` CLI used by the governance and fleet tools.

Locally it uses the admin's `gh auth` session; in automation it would use a GitHub App
installation token (GH_TOKEN). Every write goes through `call`, which honours --dry-run.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any


class GhError(RuntimeError):
    pass


class Gh:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.log: list[str] = []

    def get(self, path: str, *, allow_404: bool = False) -> Any:
        res = subprocess.run(["gh", "api", "-H", "X-GitHub-Api-Version: 2022-11-28", path],
                             capture_output=True, text=True)
        if res.returncode != 0:
            if allow_404 and ("404" in res.stderr or "Not Found" in res.stdout):
                return None
            raise GhError(f"GET {path}: {res.stderr.strip() or res.stdout.strip()}")
        return json.loads(res.stdout) if res.stdout.strip() else None

    def call(self, method: str, path: str, body: Any = None, *, ok_codes: tuple[str, ...] = ()) -> Any:
        line = f"{method} {path}" + (f"  {json.dumps(body)[:160]}" if body is not None else "")
        self.log.append(("DRY-RUN " if self.dry_run else "") + line)
        if self.dry_run:
            return None
        cmd = ["gh", "api", "-X", method, "-H", "X-GitHub-Api-Version: 2022-11-28", path]
        if body is not None:
            cmd += ["--input", "-"]
        res = subprocess.run(cmd, input=json.dumps(body) if body is not None else None, capture_output=True, text=True)
        if res.returncode != 0:
            msg = res.stderr.strip() or res.stdout.strip()
            if any(code in msg for code in ok_codes):
                self.log.append(f"   (accepted: {msg[:120]})")
                return None
            raise GhError(f"{method} {path}: {msg}")
        return json.loads(res.stdout) if res.stdout.strip() else None
