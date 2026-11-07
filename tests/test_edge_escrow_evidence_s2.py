# SPDX-License-Identifier: EUPL-1.2
"""0.29 review S2: escrow status and evidence acknowledgements were sealed on the desk's word, so a taken-over desk
could tell an edge that a break-glass value was safely with both custodians, or that its recordings were held, and the
edge would forget them. Now the signer acknowledges only what it holds itself: the evidence chain it continued, the
escrowed halves whose digest and custodians it recorded, and each custodian's own fresh sign-in, counted by it."""
import pytest
from test_edge_api import FINN, FINN_PUB, GINA, GINA_PUB, W, call, edge_server  # noqa: F401
from test_edge_two_node_end_unlock import with_proofs

from keyclerk import edge as E
from keyclerk import relay as R
from keyclerk.desk import Refusal

CTX = "escrow:plc-console:BG-1"


def escrow(base, desk) -> str:
    keys = {k["anchor"]: k["key_id"] for k in desk.store.load()["person_keys"]}
    envs = [{"key_id": keys[FINN], "envelope": R.encrypt(R.b64e(FINN_PUB), b"half-a", CTX)},
            {"key_id": keys[GINA], "envelope": R.encrypt(R.b64e(GINA_PUB), b"half-b", CTX)}]
    code, out = call(base, "POST", "/edge/escrow", {"system": "plc-console", "item_id": "BG-1", "envelopes": envs})
    assert code == 200
    pinned = call(base, "GET", "/edge-key", signed=False)[1]["key"]
    assert E.unseal(out, pinned, "kc-edge-escrow-ack-v1")["sha256"] == E.sha256(E.canonical(envs))
    return pinned


def taken(base, cookie: str, csrf: str) -> str:
    rid = next(x["relay_id"] for x in call(base, "GET", "/relay", cookie=cookie, signed=False)[1] if x["purpose"] == CTX)
    assert call(base, "POST", f"/relay/{rid}/take", cookie=cookie, csrf=csrf, signed=False)[0] == 200
    return rid


def test_an_escrow_half_counts_only_with_its_custodians_own_sign_in(edge_server, monkeypatch):
    base, desk = edge_server
    with_proofs(desk, monkeypatch)
    pinned = escrow(base, desk)
    status = lambda: E.unseal(call(base, "GET", "/edge/escrow/BG-1")[1], pinned, "kc-edge-escrow-status-v1")  # noqa: E731
    for anchor, cookie in ((FINN, "finn"), (GINA, "gina")):
        assert status()["confirmed"] is False
        rid = taken(base, cookie, "c-" + cookie)
        st = desk.relay_confirm_statement(W(anchor), rid)
        other = GINA if anchor == FINN else FINN
        for bad in (f"signed:{st['nonce']}:{other}", f"signed:another-nonce:{anchor}"):
            with pytest.raises(Refusal, match="does not sign this confirmation"):
                desk.relay_confirm(W(anchor), rid, proof=bad)
        assert desk.relay_confirm(W(anchor), rid, proof=f"signed:{st['nonce']}:{anchor}")["custodians_confirmed"] >= 1
    assert status() == {**status(), "confirmed": True, "custodians_confirmed": 2}


def test_without_approval_proofs_an_escrowed_value_is_never_confirmed(edge_server):
    base, desk = edge_server
    pinned = escrow(base, desk)
    rid = taken(base, "finn", "c-finn")
    with pytest.raises(Refusal, match="approval proofs"):
        desk.relay_confirm_statement(W(FINN), rid)
    with pytest.raises(Refusal, match="approval proofs"):
        desk.relay_confirm(W(FINN), rid, proof="signed:x:" + FINN)
    assert E.unseal(call(base, "GET", "/edge/escrow/BG-1")[1], pinned, "kc-edge-escrow-status-v1")["confirmed"] is False


def test_the_desks_escrow_record_is_not_what_the_status_counts(edge_server):
    """A desk that marks both halves confirmed in its own store changes nothing the edge is told."""
    base, desk = edge_server
    pinned = escrow(base, desk)
    item = desk.edge_store.escrow_get("plant-a", "BG-1")
    for rid in item["relay_ids"]:
        desk.edge_store.relay_take(rid)
        desk.edge_store.relay_confirm(rid)
    assert E.unseal(call(base, "GET", "/edge/escrow/BG-1")[1], pinned, "kc-edge-escrow-status-v1")["confirmed"] is False


def chain(n: int, start: int = 1, prev: str = "0" * 64) -> list[dict]:
    out = []
    for i in range(start, start + n):
        e = {"seq": i, "prev": prev, "sha256": f"{i:064x}", "size": i, "session": f"S-{i}", "at": "2026-11-07T10:00:00Z"}
        out.append(e)
        prev = E.sha256(E.canonical(e))
    return out


def test_evidence_is_acknowledged_from_the_signers_own_chain_and_a_new_signer_is_caught_up(edge_server):
    """An upgrade, or a signer whose state is new, holds no chain: the desk catches it up from its own lines, so the
    acknowledgement always names a head the signer verified from the first entry."""
    base, desk = edge_server
    entries = chain(5)
    code, out = call(base, "POST", "/edge/evidence", {"entries": entries[:3]})
    assert code == 200 and E.opened(out)["up_to_seq"] == 3
    sealer = desk.store._signer.edges()
    (sealer.dir / "evidence.json").unlink()                    # a signer that never saw this edge's chain
    code, out = call(base, "POST", "/edge/evidence", {"entries": entries[3:]})
    assert code == 200 and E.opened(out)["up_to_seq"] == 5
    assert E.opened(out)["head"] == E.sha256(E.canonical(entries[4]))
    assert sealer._read("evidence.json")["plant-a"][0] == 5


def test_a_desk_cannot_have_the_signer_acknowledge_a_head_it_did_not_continue(edge_server):
    base, desk = edge_server
    entries = chain(2)
    assert call(base, "POST", "/edge/evidence", {"entries": entries})[0] == 200
    forged = chain(3, start=3, prev="f" * 64)
    with pytest.raises(Refusal, match="holds this edge's evidence to seq 2"):
        desk._seal("evidence", "plant-a", entries=forged)
    head = call(base, "GET", "/edge/evidence")[1]
    assert E.opened(head)["up_to_seq"] == 2
