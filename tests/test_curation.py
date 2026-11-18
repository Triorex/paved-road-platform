import datetime as dt
import json
import curation_check as cc

POLICY = {"gates": {"curation": {"min_release_age_days": 7}}, "licenses": {"allow": ["MIT", "Apache-2.0", "BSD-3-Clause"]}}
NOW = dt.datetime(2026, 11, 18, tzinfo=dt.timezone.utc)


def test_parse_requirements_handles_hashes_and_extras(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("fastapi==0.120.0 \\\n    --hash=sha256:abc\nuvicorn[standard]==0.38.0  # server\n# comment\n")
    assert cc.parse_requirements(str(f)) == [("PyPI", "fastapi", "0.120.0"), ("PyPI", "uvicorn", "0.38.0")]


def test_parse_package_lock_v3(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "orders-api"},
        "node_modules/express": {"version": "5.1.0"},
        "node_modules/@scope/pkg": {"version": "1.0.0"},
        "node_modules/a/node_modules/b": {"version": "2.0.0"}}}))
    assert cc.parse_package_lock(str(f)) == [("npm", "@scope/pkg", "1.0.0"), ("npm", "b", "2.0.0"), ("npm", "express", "5.1.0")]


def test_evaluate_blocks_malicious_young_and_bad_license():
    pkgs = [("npm", "good", "1.0.0"), ("npm", "evil", "1.0.0"), ("npm", "fresh", "9.9.9"), ("npm", "gpl", "1.0.0"), ("npm", "mystery", "1.0.0")]
    old = "2025-01-01T00:00:00Z"
    metas = {
        pkgs[0]: {"published": old, "license": "MIT"},
        pkgs[1]: {"published": old, "license": "MIT"},
        pkgs[2]: {"published": "2026-11-16T00:00:00Z", "license": "MIT"},
        pkgs[3]: {"published": old, "license": "GPL-3.0-only"},
        pkgs[4]: {"published": old, "license": "UNKNOWN"},
    }
    rows = {r["name"]: r for r in cc.evaluate(pkgs, metas, {pkgs[1]: ["MAL-2025-1234"]}, POLICY, {}, NOW)}
    assert rows["good"]["problems"] == []
    assert "malicious" in rows["evil"]["problems"][0]
    assert "cooldown" in rows["fresh"]["problems"][0]
    assert "not in allowlist" in rows["gpl"]["problems"][0]
    assert rows["mystery"]["problems"] == [] and "license unknown" in rows["mystery"]["warnings"]


def test_exception_exempts_package():
    pkg = ("npm", "fresh", "9.9.9")
    rows = cc.evaluate([pkg], {pkg: {"published": "2026-11-17T00:00:00Z", "license": "MIT"}}, {}, POLICY, {"fresh==9.9.9": "EXC-9"}, NOW)
    assert rows[0]["problems"] == [] and "exempted" in rows[0]["warnings"][0]


def test_spdx_or_expression_allowed():
    pkg = ("PyPI", "dual", "1.0")
    rows = cc.evaluate([pkg], {pkg: {"published": "2025-01-01T00:00:00Z", "license": "(MIT OR GPL-2.0-only)"}}, {}, POLICY, {}, NOW)
    assert rows[0]["problems"] == []
