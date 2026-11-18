import check_pinned_actions as cpa

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def make(tmp_path, body):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(body)
    return str(tmp_path)


def test_sha_pins_and_local_and_docker_digest_pass(tmp_path):
    root = make(tmp_path, f"""jobs:
  a:
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
      - uses: ./.github/actions/local
      - uses: docker://alpine@sha256:{'a' * 64}
  b:
    uses: Triorex/paved-road-platform/.github/workflows/pr-security.yml@{SHA}
""")
    assert cpa.scan(root) == []


def test_tags_and_branches_fail(tmp_path):
    root = make(tmp_path, """jobs:
  a:
    steps:
      - uses: actions/checkout@v7
      - uses: some/action@main
      - uses: docker://alpine:3.20
""")
    assert [r for _, _, r in cpa.scan(root)] == ["actions/checkout@v7", "some/action@main", "docker://alpine:3.20"]
