# SPDX-License-Identifier: EUPL-1.2
"""Decision 0019 point 5: a restored desk takes its mark's sources from the heads edges echoed (edge protocol 1.4) and
the witness's countersigned checkpoint; the sources propose, two people still confirm."""
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import restore
from keyclerk import witness as W
from keyclerk.restore import RestoreMode
from keyclerk.store import merkle
from keyclerk.store import note as N
from test_edge_api import call, edge_server  # noqa: F401

ORIGIN = "keyclerk.example/restore-test"


def test_heads_edges_echo_in_restore_mode_are_a_source_of_the_mark(edge_server):
    base, desk = edge_server
    restore.start(desk.store.path)
    for rev in (7, 12, 9):                                          # the highest one is kept
        code, _ = call(base, "POST", "/edge/report", {"applied_serial": 3, "attestation": {"profile": "basic"},
                                                      "drift": [], "records_head": {"revision": rev, "head": "ab" * 32}})
        assert code == 503                                            # still an outage to the edge
    m = restore.marker(desk.store.path)
    assert m["edges"]["plant-a"] == 3 and m["heads"]["plant-a"]["revision"] == 12
    src = restore.mark_sources(m)
    assert src["edges"]["revision"] == 12 and src["proposed"] == 12 and "two people" in src["note"]


def test_a_malformed_head_in_restore_mode_is_refused(edge_server):
    base, desk = edge_server
    restore.start(desk.store.path)
    code, _ = call(base, "POST", "/edge/report", {"applied_serial": 3, "attestation": {"profile": "basic"},
                                                  "drift": [], "records_head": {"revision": "12"}})
    assert code == 400


@pytest.fixture
def witnessed(tmp_path):
    rk, wk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    w = W.Witness(wk, "witness.example/r1", tmp_path / "w", [N.vkey(ORIGIN, N.LOG, N.raw_public(rk))])
    leaves = [merkle.leaf(f"l{i}".encode()) for i in range(30)]
    text = N.checkpoint_text(ORIGIN, 30, merkle.mth(leaves))
    assert w.add_checkpoint(W.request_body(0, [], text + "\n" + N.sign(text, ORIGIN, rk)))[0] == 200
    srv = W.serve(w, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{srv.server_address[1]}", "vkey": w.vkey, "records": N.raw_public(rk).hex()}
    srv.shutdown()


def test_the_witness_counts_the_links_the_restored_log_lost(witnessed):
    got = restore.witness_mark(witnessed["url"], witnessed["vkey"], ORIGIN, witnessed["records"])
    assert got["size"] == 30
    src = restore.mark_sources({"heads": {"plant-a": {"revision": 20, "head": "ab" * 32}}},
                               {"size": 22, "revision": 19}, got)
    assert src["witness"]["revision"] == 19 + 8 and src["proposed"] == 27     # 8 links the restore lost


def test_a_witness_checkpoint_not_signed_by_the_records_key_is_no_source(witnessed):
    other = N.raw_public(Ed25519PrivateKey.generate()).hex()
    with pytest.raises(RestoreMode, match="not signed by the records key"):
        restore.witness_mark(witnessed["url"], witnessed["vkey"], ORIGIN, other)
    with pytest.raises(RestoreMode, match="serves no checkpoint"):
        restore.witness_mark(witnessed["url"], witnessed["vkey"], "keyclerk.example/other", witnessed["records"])
