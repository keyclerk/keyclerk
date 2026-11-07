# SPDX-License-Identifier: EUPL-1.2
"""0.29 review S5: an unlock proof had no expiry or single use at the signer, so a desk that kept an approver's
sign-in could have codes read with it again later. Now the signer takes a sign-in only from the last ten minutes by its
clock, and each sign-in reads one code."""
import time

import pytest
from test_edge_api import edge_server  # noqa: F401
from test_edge_two_node_end_unlock import BODY, GINA, NODE2, W, _Proofs, two_nodes, with_proofs  # noqa: F401

from keyclerk import edge as E
from keyclerk.desk import Refusal


def test_a_sign_in_reads_one_code(two_nodes, monkeypatch):
    _, desk, _ = two_nodes
    with_proofs(desk, monkeypatch)
    req = {**BODY, "node": E.key_id(E.public_hex(NODE2))}
    st = desk.unlock_statement(W(GINA), "plant-u", req)
    proof = f"signed:{st['nonce']}:{GINA}"
    assert desk.phoned_unlock(W(GINA), "plant-u", req, proof=proof)["code"]
    with pytest.raises(Refusal, match="already read an unlock code"):
        desk.phoned_unlock(W(GINA), "plant-u", req, proof=proof)


def test_an_old_sign_in_reads_nothing(two_nodes, monkeypatch):
    _, desk, _ = two_nodes
    with_proofs(desk, monkeypatch)
    old = _Proofs()
    old.issued = time.time() - 11 * 60
    desk.store._signer.proofs = old
    req = {**BODY, "node": E.key_id(E.public_hex(NODE2))}
    st = desk.unlock_statement(W(GINA), "plant-u", req)
    with pytest.raises(Refusal, match="last 10 minutes"):
        desk.phoned_unlock(W(GINA), "plant-u", req, proof=f"signed:{st['nonce']}:{GINA}")
