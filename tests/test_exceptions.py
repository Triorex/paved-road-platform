import check_exceptions as ce

BASE = {"type": "cve", "target": "CVE-2026-0001", "reason": "no fix upstream", "compensating_controls": "WAF rule",
        "owner": "@Triorex/payments-team", "approved_by": "@Triorex/appsec"}


def run(tmp_path, exceptions, today="2026-11-18", extra=()):
    import yaml
    f = tmp_path / "exceptions.yaml"
    f.write_text(yaml.safe_dump({"exceptions": exceptions}))
    return ce.main(["--file", str(f), "--today", today, *extra])


def test_valid_exception_passes_and_emits_trivyignore(tmp_path):
    out = tmp_path / ".trivyignore"
    assert run(tmp_path, [{**BASE, "id": "EXC-1", "expires": "2026-12-31"}], extra=["--emit-trivyignore", str(out)]) == 0
    assert "CVE-2026-0001" in out.read_text()


def test_expired_exception_fails(tmp_path):
    assert run(tmp_path, [{**BASE, "id": "EXC-2", "expires": "2026-11-01"}]) == 1


def test_exception_longer_than_max_days_fails(tmp_path):
    assert run(tmp_path, [{**BASE, "id": "EXC-3", "expires": "2027-06-01"}]) == 1


def test_missing_fields_fail(tmp_path):
    assert run(tmp_path, [{"id": "EXC-4", "type": "cve", "expires": "2026-12-01"}]) == 1


def test_no_file_is_fine(tmp_path):
    assert ce.main(["--file", str(tmp_path / "missing.yaml")]) == 0
