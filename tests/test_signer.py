# SPDX-License-Identifier: EUPL-1.2
"""Decision 0015 (replan D1): the checking signer holds the records key and signs a revision only after its own checks."""
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from keyclerk import records
from keyclerk.desk import Desk, Store
from keyclerk.signer import Signer, SignerClient, SignerRefused, serve

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ANN = {"anchor": "idp:7c1f-ann", "roles": []}


@pytest.fixture
def signed_desk(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer-state")
    token = tmp_path / "token"
    token.write_text("t0ken-for-tests", encoding="utf-8")
    srv = serve(signer, "tcp:127.0.0.1:0", "t0ken-for-tests")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    client = SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(token))
    desk = Desk(Store(tmp_path / "store", None, FIXTURES / "records.yaml", signer=client))
    yield desk, signer, client, tmp_path
    srv.shutdown()


def test_a_desk_with_a_signer_holds_no_records_key_and_its_changes_still_apply(signed_desk):
    desk, signer, client, tmp = signed_desk
    assert desk.store._key is None and desk.store.public_key_hex() == signer.public_key()
    r = desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5})
    assert r["outcome"] == "applied" and desk.store.revision() == 2
    assert desk.store.verify_log() == []
    desk.store.close()
    again = Store(tmp / "store", None, signer=client)        # a restart verifies what the signer signed
    assert again.revision() == 2


def test_the_signer_refuses_what_the_engine_or_the_history_would_refuse(signed_desk):
    desk, signer, client, tmp = signed_desk
    doc = desk.store.load()
    raw_ok = yaml.safe_dump({**{k: v for k, v in doc.items() if k not in ("visits", "visit_events", "badges")}, "revision": 2},
                            sort_keys=False, default_flow_style=False)
    import hashlib
    import json
    def body(raw, rev):
        b = {"seq": 99, "at": "2026-10-23T12:00:00Z", "revision": rev, "action": "forged", "actor": None, "outcome": "applied",
             "records_sha256": hashlib.sha256(raw.encode()).hexdigest(), "prev": "0" * 64}
        b["sha256"] = hashlib.sha256(json.dumps(b, sort_keys=True).encode()).hexdigest()
        return b
    with pytest.raises(SignerRefused, match="exactly one higher"):
        client.commit(raw_ok.replace("revision: 2", "revision: 5"), body(raw_ok.replace("revision: 2", "revision: 5"), 5))
    gone = yaml.safe_load(raw_ok)
    gone["memberships"] = gone["memberships"][1:]               # a deleted membership: history rewritten
    raw_gone = yaml.safe_dump(gone, sort_keys=False)
    with pytest.raises(SignerRefused, match="history rewritten"):
        client.commit(raw_gone, body(raw_gone, 2))
    bad = yaml.safe_load(raw_ok)
    bad["memberships"].append({"membership_id": "M-example-0999", "group": "admins", "member": {"anchor": "idp:66cc-finn"},
                               "by": "idp:7c1f-ann", "under": "D-example-0001", "start": "2026-10-23T00:00:00Z",
                               "end": "2026-11-01T00:00:00Z"})
    raw_bad = yaml.safe_dump(bad, sort_keys=False)
    with pytest.raises(SignerRefused, match="checks refuse"):
        client.commit(raw_bad, body(raw_bad, 2))
    with pytest.raises(SignerRefused, match="only with its commit"):
        client.sign_line(body(raw_ok, 2))
    assert desk.store.revision() == 1                           # nothing of it was committed


def test_over_tcp_the_signer_answers_only_the_desk(signed_desk):
    desk, signer, client, tmp = signed_desk
    stranger = SignerClient(client.address)
    with pytest.raises(SignerRefused, match="wrong token"):
        stranger.public_key()


def test_a_signer_adopts_a_store_that_signed_in_its_own_process_once(tmp_path):
    key = Ed25519PrivateKey.generate()
    kf = tmp_path / "records.key"
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    kf.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="ascii")
    old = Desk(Store(tmp_path / "store", kf, FIXTURES / "records.yaml"))
    old.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5})
    old.store.close()
    st = tmp_path / "store"
    signer = Signer(key, tmp_path / "signer-state")
    assert signer.adopt((st / "records.yaml").read_text(encoding="utf-8"), (st / "records.yaml.sig").read_text(encoding="ascii")) == 2
    with pytest.raises(SignerRefused, match="already holds"):
        signer.adopt((st / "records.yaml").read_text(encoding="utf-8"), (st / "records.yaml.sig").read_text(encoding="ascii"))
    stranger = Signer(Ed25519PrivateKey.generate(), tmp_path / "other")
    with pytest.raises(SignerRefused, match="not signed with this key"):
        stranger.adopt((st / "records.yaml").read_text(encoding="utf-8"), (st / "records.yaml.sig").read_text(encoding="ascii"))
