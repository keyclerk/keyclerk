# SPDX-License-Identifier: EUPL-1.2
"""Restore safety (decision 0019 point 5, issue 27): a desk restored from an older backup writes nothing and tells
edges to wait until the high-water mark is confirmed, then resumes above it, so no revision number and no edge bundle
serial is ever signed twice."""
import hashlib
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from tests.test_api import ANN, FIXTURES

from keyclerk import restore
from keyclerk.desk import Desk, Store
from keyclerk.health import Readiness

OFFICER, ROOT = "idp:31ee-ingrid", "idp:2b9e-owner"
REALM = "example"
PEOPLE = ["idp:44aa-dirk", "idp:66cc-finn", "idp:55bb-eva"]


def _desk(store_dir, key):
    return Desk(Store(store_dir, key, FIXTURES / "records.yaml"))


def _change(desk, i):
    r = desk.propose(ANN, {"action": "add_member", "group": "office-staff" if i % 2 else "office",
                           "anchor": PEOPLE[i % len(PEOPLE)], "days": 30 + i})
    assert r["outcome"] == "applied", r


def proofs_for(store_dir, mark, *people):
    """Tokens a fake broker accepts: each names the nonce it was signed for."""
    sha = hashlib.sha256((store_dir / "records.yaml").read_bytes()).hexdigest()
    return {by: json.dumps({"nonce": restore.statement(REALM, by, mark, sha), "by": by}) for by in people}


def verify(token, nonce, by):
    t = json.loads(token)
    if t["nonce"] != nonce or t["by"] != by:
        raise ValueError("this proof is for another statement")


@pytest.fixture
def restored(tmp_path):
    """A desk at revision 5 whose backup was taken at revision 3; an edge had applied bundle 9. The store is put back
    from the backup and started in restore mode."""
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    live = tmp_path / "store"
    desk = _desk(live, key)
    _change(desk, 1)
    _change(desk, 2)
    assert desk.store.revision() == 3
    desk.store.close()
    shutil.copytree(live, tmp_path / "backup")                    # the backup, at revision 3
    desk = _desk(live, key)
    _change(desk, 3)
    _change(desk, 4)
    assert desk.store.revision() == 5
    desk.edge_store.update_state("edge-a", serial=9)
    desk.store.close()
    shutil.rmtree(live)                                           # the disk is lost
    shutil.copytree(tmp_path / "backup", live)
    restore.start(live)
    desk = _desk(live, key)
    yield desk, live, key
    desk.store.close()


def test_a_desk_in_restore_mode_writes_nothing_is_not_ready_and_edges_wait(restored):
    desk, live, _ = restored
    with pytest.raises(restore.RestoreMode):
        desk.propose(ANN, {"action": "add_member", "group": "office", "anchor": "idp:44aa-dirk", "days": 30})
    assert desk.store.revision() == 3
    with pytest.raises(restore.RestoreMode):
        desk.edge_bundle("edge-a")
    with pytest.raises(restore.RestoreMode):
        desk.edge_report("edge-a", {"applied_serial": 9})          # the edge says what it applied, and waits
    assert restore.marker(live)["edges"] == {"edge-a": 9}
    detail = Readiness(desk).detail()
    assert detail["ready"] is False and detail["checks"]["restore"]["ok"] is False


def test_resuming_above_the_confirmed_mark_never_signs_a_number_twice(restored):
    desk, live, key = restored
    with pytest.raises(restore.RestoreMode):
        desk.edge_report("edge-a", {"applied_serial": 9})
    desk.store.close()
    store = Store(live, key)
    out = restore.resume(store, desk.edge_store, live, REALM, 5, proofs_for(live, 5, OFFICER, ROOT), verify)
    assert out["revision"] == 6 and out["lost"] == 2 and out["edges_raised"] == {"edge-a": 9}
    assert restore.marker(live) is None
    assert desk.edge_store.next_serial("edge-a") == 10            # the edge's next bundle is above the one it holds
    store.close()
    after = _desk(live, key)
    _change(after, 5)
    assert after.store.revision() == 7                            # 4 and 5 are never signed again
    lines = [json.loads(x) for x in (live / "log.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    resumed = [e for e in lines if e.get("action") == "restore_resumed"]
    assert resumed and "lost" in resumed[0]["summary"] and any("incident" in r for r in resumed[0]["reasons"])
    after.store.close()


@pytest.mark.parametrize("people, why", [
    ((OFFICER,), "root trust owner"),
    ((ROOT,), "security officer"),
    ((OFFICER, ANN["anchor"]), "neither the security officer nor a root trust owner"),
])
def test_two_people_confirm_the_mark_the_officer_and_a_root_trust_owner(restored, people, why):
    desk, live, key = restored
    desk.store.close()
    store = Store(live, key)
    with pytest.raises(restore.RestoreMode, match=why):
        restore.resume(store, desk.edge_store, live, REALM, 5, proofs_for(live, 5, *people), verify)
    assert restore.marker(live) is not None and store.revision() == 3
    store.close()


def test_a_confirmation_for_another_mark_does_not_count(restored):
    desk, live, key = restored
    desk.store.close()
    store = Store(live, key)
    with pytest.raises(restore.RestoreMode, match="does not hold"):
        restore.resume(store, desk.edge_store, live, REALM, 9, proofs_for(live, 5, OFFICER, ROOT), verify)
    store.close()


def test_a_mark_below_the_restored_revision_is_refused(restored):
    desk, live, key = restored
    desk.store.close()
    store = Store(live, key)
    with pytest.raises(restore.RestoreMode, match="below the restored revision"):
        restore.resume(store, desk.edge_store, live, REALM, 2, proofs_for(live, 2, OFFICER, ROOT), verify)
    store.close()


def test_the_api_answers_restore_mode_with_503(tmp_path):
    from tests.test_api_refusal_need_to_know import start
    from tests.test_api import req
    srv, base, desk = start(tmp_path)
    try:
        restore.start(desk.store.path)
        code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "office",
                                                             "anchor": "idp:44aa-dirk", "days": 30},
                            cookie="ann", csrf="csrf-ann")
        assert code == 503 and json.loads(body)["error"]["code"] == "restoring"
    finally:
        srv.shutdown()
