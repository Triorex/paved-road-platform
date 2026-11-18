"""Contract test: every caller template grants at least the permissions of every job it calls.

GitHub validates the permissions of all jobs in a called workflow, even jobs an `if` would skip,
and fails the whole run at startup when a caller grants less. v1.0.3-rc.1 shipped exactly that
defect (record-release needed contents: write under the staging caller); this test stops it.
"""
import glob
import os
import re

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")
LEVEL = {"none": 0, "read": 1, "write": 2}
USES = re.compile(r"Triorex/paved-road-platform/\.github/workflows/([\w-]+\.yml)@")


def needed(workflow_file):
    with open(os.path.join(ROOT, ".github", "workflows", workflow_file)) as fh:
        wf = yaml.safe_load(fh)
    need = {}
    for job in (wf.get("jobs") or {}).values():
        for scope, level in (job.get("permissions") or {}).items():
            need[scope] = max(need.get(scope, 0), LEVEL[level])
    return need


def test_every_template_caller_grants_what_its_called_workflow_needs():
    problems = []
    for tmpl in glob.glob(os.path.join(ROOT, "fleet", "templates", "*.yml.tmpl")):
        text = open(tmpl).read().replace("{{PLATFORM_SHA}}", "0" * 40)
        doc = yaml.safe_load(re.sub(r"\{\{\w+\}\}", "x", text))
        for name, job in (doc.get("jobs") or {}).items():
            m = USES.search(str(job.get("uses", "")))
            if not m:
                continue
            granted = {k: LEVEL[v] for k, v in (job.get("permissions") or {}).items()}
            for scope, level in needed(m.group(1)).items():
                if granted.get(scope, 0) < level:
                    problems.append(f"{os.path.basename(tmpl)}:{name} grants {scope}="
                                    f"{[k for k, v in LEVEL.items() if v == granted.get(scope, 0)][0]} "
                                    f"but {m.group(1)} needs {[k for k, v in LEVEL.items() if v == level][0]}")
    assert not problems, "\n".join(problems)
