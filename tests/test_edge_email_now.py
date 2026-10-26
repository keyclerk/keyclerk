# SPDX-License-Identifier: EUPL-1.2
"""The address answers only what the officer's ceiling and independence allow now."""
from keyclerk import edge as E
from keyclerk import edge_records
from tests.test_edge_api import ANN, OFFICER_KEY, call, ceiling, edge_server  # noqa: F401 - fixture


def test_no_address_for_a_lease_the_ceiling_no_longer_allows(edge_server):
    base, desk = edge_server
    assert call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, ceiling(1))},
                cookie="eva", csrf="c-eva", signed=False)[0] == 200
    b = call(base, "GET", "/edge/bundle")[1]
    lease = next(x for x in E.opened(b)["leases"] if x["person"] == ANN)
    narrowed = {**ceiling(2), "persons": [], "roles": []}                     # Ann is no longer inside
    assert call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, narrowed)},
                cookie="eva", csrf="c-eva", signed=False)[0] == 200
    # the desk would now cut no lease for Ann; the edge does not pull
    code, _ = call(base, "GET", f"/edge/lease/{lease['lease_id']}/email")
    assert code == 404, "address served for a lease the officer's current ceiling refuses"


def test_no_address_once_the_officer_is_not_independent(edge_server, monkeypatch):
    base, desk = edge_server
    call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, ceiling(1))},
         cookie="eva", csrf="c-eva", signed=False)
    lease = E.opened(call(base, "GET", "/edge/bundle")[1])["leases"][0]
    monkeypatch.setattr(edge_records, "officer_errors", lambda doc, e, at: ["plant-a: the officer joined the core"])
    code, _ = call(base, "GET", f"/edge/lease/{lease['lease_id']}/email")
    assert code != 200, "address served although the officer is no longer independent (flag only set at a cut)"
