# SPDX-License-Identifier: EUPL-1.2
"""Only the reconciler records a broker subject: the desk's credential cannot (decision 0028, amendment of 2026-10-26)."""
import threading
import uuid

import pytest
from tests.test_approvals import AUD, ISS, Broker  # noqa: F401
from tests.test_signer_replica import world  # noqa: F401 - fixture

from keyclerk import anchors as A
from keyclerk import approvals
from keyclerk.signer import SignerClient, SignerRefused, serve
from keyclerk.store import replay as RP
from keyclerk.store.log_reconcile import Identities


def test_a_desk_token_cannot_point_a_holders_anchor_at_the_others_subject(world, tmp_path):
    s = world["signer"]
    holder = A.inward(s.replica, "idp:7c1f-ann")
    assert holder and s.replica.side_get("anchor_map", holder).get("sub") is None      # phase 1: not linked yet
    other_sub = str(uuid.uuid4())

    srv = serve(s, "tcp:127.0.0.1:0", "desk-token")              # the one token the desk holds
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    tok = tmp_path / "token"
    tok.write_text("desk-token", encoding="utf-8")
    desk = SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(tok))
    try:
        try:
            desk.link_subject(holder, other_sub)              # the compromised desk, not the reconciler
        except SignerRefused:
            return                                               # fixed: the desk cannot link subjects
    finally:
        srv.shutdown()
        srv.server_close()

    # the other's own fresh sign-in at the broker (their own sub, their own anchor attribute) as an approval proof
    broker = Broker()
    proofs = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/realms/example/protocol/openid-connect/certs",
                                    tmp_path / "keys.json", fetch=broker.jwks)
    proofs.resolve = lambda claims: A.resolve(s.replica, claims)          # as Signer._refuse sets it
    token = broker.token("nonce-of-some-statement", "idp:ffff-mallory", sub=other_sub)
    taken = True
    try:
        proofs(token, "nonce-of-some-statement", holder)
    except Exception:   # noqa: BLE001
        taken = False
    ids = Identities(RP.records(s.replica), s.replica)
    assert not taken, "the other's own sign-in verifies as the holder's approval proof"
    assert ids.out(holder) != f"uid:{other_sub}", "the reconciler would write the holder's access to the other"
