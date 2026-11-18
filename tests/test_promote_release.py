import promote_release as pr


def repo(name, exists=True, deps=()):
    return {"name": name, "exists": exists, "deployments": list(deps)}


def test_promotes_when_platform_ci_and_every_existing_ring0_repo_has_production_evidence():
    ok, reasons = pr.evaluate(True, [repo("payments-api", deps=[{"pins_rc": True, "success": True}]),
                                     repo("orders-api", exists=False)])
    assert ok and reasons == []


def test_blocks_without_production_pinned_to_candidate():
    ok, reasons = pr.evaluate(True, [repo("payments-api", deps=[{"pins_rc": False, "success": True},
                                                                 {"pins_rc": True, "success": False}])])
    assert not ok and "payments-api" in reasons[0]


def test_blocks_when_platform_ci_failed_or_no_ring0_exists():
    assert not pr.evaluate(False, [repo("payments-api", deps=[{"pins_rc": True, "success": True}])])[0]
    assert not pr.evaluate(True, [repo("payments-api", exists=False)])[0]
