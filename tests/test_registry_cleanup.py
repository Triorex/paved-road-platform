import datetime as dt
import registry_cleanup as rc

NOW = dt.datetime(2026, 11, 30, tzinfo=dt.timezone.utc)
D = lambda n: "sha256:" + f"{n:064x}"  # noqa: E731


def v(id_, digest, tags, days_old):
    created = (NOW - dt.timedelta(days=days_old)).isoformat().replace("+00:00", "Z")
    return {"id": id_, "name": digest, "created_at": created, "metadata": {"container": {"tags": tags}}}


def test_keeps_promoted_newest_and_recent_and_deletes_old_unpromoted_with_companions():
    versions = [
        v(1, D(1), ["sha-" + "1" * 40, "production", "staging"], 20),      # promoted -> keep
        v(2, D(2), ["sha-" + "2" * 40], 1),                                 # recent -> keep
        v(3, D(3), ["sha-" + "3" * 40], 15),                                # old, unpromoted, beyond keep-last -> delete
        v(4, D(4), [f"sha256-{3:064x}.sig"], 15),                          # companion of 3 -> delete
        v(5, D(5), [f"sha256-{3:064x}.att"], 15),                          # companion of 3 -> delete
        v(6, D(6), [f"sha256-{1:064x}.sig"], 20),                          # companion of promoted -> keep
        v(7, D(7), [], 30),                                                 # untagged -> always keep
    ]
    keep, delete = rc.plan(versions, keep_last=1, min_age_days=7, now=NOW)
    assert sorted(x["id"] for x in delete) == [3, 4, 5]
    assert {1, 2, 6, 7} <= {x["id"] for x in keep}


def test_keep_last_protects_recent_builds():
    versions = [v(i, D(i), ["sha-" + str(i) * 40], 30 + i) for i in range(1, 6)]
    keep, delete = rc.plan(versions, keep_last=3, min_age_days=7, now=NOW)
    assert sorted(x["id"] for x in keep) == [1, 2, 3] and sorted(x["id"] for x in delete) == [4, 5]
