# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 1: a high-availability edge is two nodes to the desk. Either node's enrolment key signs its
requests, the desk knows which one did, and keeps each node's last pull and report apart. A one-node edge is unchanged."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import edge_records
from test_edge_api import EDGE_KEY, _bundle_with_ceiling, call, edge_server  # noqa: F401

NODE2 = Ed25519PrivateKey.from_private_bytes(b"n" * 32)


def test_either_nodes_key_signs_and_the_desk_knows_which():
    k1, k2 = E.public_hex(EDGE_KEY), E.public_hex(NODE2)
    for key, want in ((EDGE_KEY, k1), (NODE2, k2)):
        h = E.sign_request(key, "edge-a", "GET", "/api/v1/edge/bundle", b"")
        assert E.check_request_node(h, "GET", "/api/v1/edge/bundle", b"", lambda e: [k1, k2], E.Replay()) == ("edge-a", want)
    other = E.sign_request(Ed25519PrivateKey.generate(), "edge-a", "GET", "/api/v1/edge/bundle", b"")
    with pytest.raises(ValueError, match="not a request signed by an enrolled edge"):
        E.check_request_node(other, "GET", "/api/v1/edge/bundle", b"", lambda e: [k1, k2], E.Replay())
    one = E.sign_request(EDGE_KEY, "edge-a", "GET", "/api/v1/edge/bundle", b"")       # a one-node edge, as before
    assert E.check_request(one, "GET", "/api/v1/edge/bundle", b"", lambda e: k1, E.Replay()) == "edge-a"


def test_a_rotation_states_the_second_node_and_node_keys_list_both():
    e = {"edge_id": "edge-a", "enrolment_key": "a" * 64, "officer": "x", "officer_key": "b" * 64, "at": "2026-11-01T00:00:00Z"}
    rot = {"edge": "edge-a", "enrolment_key": "c" * 64, "officer": "x", "officer_key": "b" * 64,
           "at": "2026-11-02T00:00:00Z", "node2": {"enrolment_key": "d" * 64}}
    from datetime import datetime, timezone
    now = datetime(2026, 11, 3, tzinfo=timezone.utc)
    assert edge_records.node_keys(edge_records.current({"edge_rotations": [rot]}, e, now)) == ["c" * 64, "d" * 64]
    assert edge_records.node_keys(edge_records.current({"edge_rotations": [{**rot, "node2": None}]},
                                                       {**e, "node2": {"enrolment_key": "e" * 64}}, now)) == ["c" * 64]


def test_the_desk_keeps_each_nodes_pull_and_report_apart(edge_server, monkeypatch):
    base, desk = edge_server
    _bundle_with_ceiling(base)
    k1 = desk.edge_keys_of("plant-a")[0]
    monkeypatch.setattr(desk, "edge_keys_of", lambda eid: [k1, E.public_hex(NODE2)])
    h = lambda key, method, path, body=b"": E.sign_request(key, "plant-a", method, "/api/v1" + path, body)   # noqa: E731
    assert call(base, "GET", "/edge/bundle", header=h(NODE2, "GET", "/edge/bundle"))[0] == 200
    import json
    report = {"applied_serial": 1, "attestation": {"profile": "basic"}, "drift": []}
    raw = json.dumps(report).encode()
    assert call(base, "POST", "/edge/report", report, header=h(NODE2, "POST", "/edge/report", raw))[0] == 200
    nodes = desk.edge_store.state("plant-a")["nodes"]
    assert E.key_id(E.public_hex(NODE2)) in nodes and nodes[E.key_id(E.public_hex(NODE2))]["last_report"]
    assert E.key_id(k1) in nodes and "last_report" not in nodes[E.key_id(k1)]      # the other node pulled, never reported
