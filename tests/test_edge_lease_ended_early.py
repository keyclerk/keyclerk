# SPDX-License-Identifier: EUPL-1.2
"""Decision 0029 point 8: an edge reports a bastion taking away a lease's assignment before the lease expired, on
any bastion. Only a lease of its last bundle, ended before its expiry, is such an incident."""
from datetime import datetime, timedelta

from test_edge_api import ANN, _bundle_with_ceiling, call, edge_server  # noqa: F401


def _lease(base):
    return next(x for x in _bundle_with_ceiling(base)["leases"] if x["person"] == ANN)


def _at(until: str, hours: float) -> str:
    t = datetime.fromisoformat(until.replace("Z", "+00:00")) + timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_an_assignment_ended_before_the_expiry_reaches_the_officer(edge_server):
    base, _ = edge_server
    lease = _lease(base)
    code, out = call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "lease_id": lease["lease_id"],
                                                      "system": "bastion-a", "at": _at(lease["until"], -0.5),
                                                      "detail": "role removed at sign-in"})
    assert code == 200, out
    code, edges = call(base, "GET", "/edges", cookie="eva", signed=False)
    seen = edges[0]["incidents"][-1]
    assert seen["kind"] == "lease_ended_early" and seen["lease_id"] == lease["lease_id"] and seen["until"] == lease["until"]


def test_an_assignment_that_ends_at_the_expiry_is_no_incident(edge_server):
    base, _ = edge_server
    lease = _lease(base)
    code, out = call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "lease_id": lease["lease_id"],
                                                      "system": "bastion-a", "at": _at(lease["until"], 0)})
    assert code >= 400 and "ended on time" in out["error"]["message"], out


def test_a_lease_the_desk_no_longer_lists_is_no_incident(edge_server):
    base, _ = edge_server
    lease = _lease(base)
    code, out = call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "lease_id": "L-not-here",
                                                      "system": "bastion-a", "at": _at(lease["until"], -1)})
    assert code >= 400 and "not in this edge's last bundle" in out["error"]["message"], out


def test_the_lease_and_the_kind_go_together(edge_server):
    base, _ = edge_server
    lease = _lease(base)
    at = _at(lease["until"], -1)
    assert call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "system": "bastion-a", "at": at})[0] == 400
    assert call(base, "POST", "/edge/incident", {"kind": "drift", "lease_id": lease["lease_id"], "at": at})[0] == 400
    assert call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "lease_id": lease["lease_id"],
                                                 "system": "bastion-a", "at": "yesterday"})[0] == 400
    assert call(base, "POST", "/edge/incident", {"kind": "lease_ended_early", "lease_id": lease["lease_id"],
                                                 "at": at})[0] == 400                      # which bastion: required
