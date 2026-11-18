import json
import sarif_gate


def write(tmp_path, results):
    doc = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}}, "results": results}]}
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc))
    return str(p)


def test_error_level_blocks_in_enforce(tmp_path):
    f = write(tmp_path, [{"ruleId": "sqli", "level": "error"}, {"ruleId": "style", "level": "note"}])
    assert sarif_gate.main([f, "--name", "SAST", "--mode", "enforce"]) == 1


def test_audit_mode_never_blocks(tmp_path):
    f = write(tmp_path, [{"ruleId": "sqli", "level": "error"}])
    assert sarif_gate.main([f, "--name", "SAST", "--mode", "audit"]) == 0


def test_warnings_do_not_block(tmp_path):
    f = write(tmp_path, [{"ruleId": "weak", "level": "warning"}])
    assert sarif_gate.main([f, "--name", "SAST"]) == 0
