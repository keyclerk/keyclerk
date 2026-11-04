# SPDX-License-Identifier: EUPL-1.2
"""Backups forget (decision 0028 point 6, 0029 point 6): a visit erased after a backup was taken stays erased when that
backup is restored, on both stores, because a restore applies the newest erasure journal before the desk serves and is
refused without one. A restored signer signs nothing at positions it may have lost until it recovered them."""
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_visits import register, visit_desk  # noqa: F401

from keyclerk import age, backup, config, restore
from keyclerk.edge_store import EdgeStore
from keyclerk.signer import Signer, SignerRefused

ERASE_AT = datetime(2026, 11, 26, 17, 0, tzinfo=timezone.utc)      # past the fixture visit's retention


@pytest.fixture
def policy(monkeypatch):
    ids = [age.keygen() for _ in range(2)]
    cfg = {**config.current(), "backup": {"recipients": [i[1] for i in ids]}}
    monkeypatch.setattr(config, "current", lambda: cfg)
    key = Ed25519PrivateKey.generate()
    return {"ids": ids, "key": key, "pin": backup.public_hex(key)}


def _erase_after_backup(tmp_path, policy, kind):
    desk = visit_desk(tmp_path, kind)
    register(desk)
    vid = desk.store.visit_ids()[0]
    signer = getattr(desk, "test_signer", None)
    records = signer.public_key() if signer else desk.store.public_key_hex()
    archive, manifest, _ = backup.take(tmp_path / "out", records, policy["key"], desk=tmp_path / "store",
                                       signer_state=tmp_path / "signer" if signer else None)
    desk.test_clock.t = ERASE_AT
    desk.tick()
    assert vid not in desk.store.visit_ids()                      # erased on the live desk, after the backup
    journal = tmp_path / "out" / "now.erasures.json"
    backup.write_erasures(tmp_path / "store", policy["key"], journal)
    return desk, vid, records, archive, manifest, journal


def test_a_visit_erased_after_the_backup_stays_erased_on_the_yaml_store(tmp_path, policy):
    from keyclerk.desk import Store
    desk, vid, records, archive, manifest, journal = _erase_after_backup(tmp_path, policy, "yaml")
    key = desk.store.key_path
    desk.store.close()
    to = tmp_path / "restored"
    out = backup.restore(archive, manifest, [policy["pin"]], records, [policy["ids"][0][0]], to, journal)
    assert out["erasures_to_apply"] == 1 and restore.marker(to / "desk")["erasures"] == [vid]
    store = Store(to / "desk", key)
    try:
        assert vid in store.visit_ids()                           # the backup brought it back
        assert restore.apply_erasures(store, to / "desk") == [vid]
        assert vid not in store.visit_ids() and store.verify_log() == []
        last = json.loads((to / "desk" / "log.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        assert last["action"] == "visit_erased" and last["visits"] == {vid: None}
    finally:
        store.close()


def test_a_change_log_desk_leaves_restore_mode_with_the_journal_applied(tmp_path, policy):
    from keyclerk.store.log_desk import LogStore
    desk, vid, records, archive, manifest, journal = _erase_after_backup(tmp_path, policy, "sqlite")
    live = desk.test_signer
    to = tmp_path / "restored"
    backup.restore(archive, manifest, [policy["pin"]], records, [policy["ids"][1][0]], to, journal)
    s = Signer(live.key, to / "signer")
    try:
        with pytest.raises(SignerRefused, match="restored from a backup"):
            s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": [], "entry": {}}, [])
    finally:
        s.close()
    restore.recover_log(to / "signer", live.replica, records)     # the signer stopped: its lost links back
    s = Signer(live.key, to / "signer")
    st = LogStore(to / "desk", s)
    try:
        with pytest.raises(restore.RestoreMode):
            st.commit(st.load(), {})                                # the desk still writes nothing
        out = restore.leave(st, EdgeStore(to / "desk"), to / "desk")
        assert out["erased"] == [vid] and vid not in st.visit_ids() and restore.marker(to / "desk") is None
    finally:
        st.close()
        s.close()
        desk.store.close()


def test_a_desk_is_restored_only_with_a_current_authentic_journal(tmp_path, policy):
    desk, _, records, archive, manifest, journal = _erase_after_backup(tmp_path, policy, "yaml")
    desk.store.close()
    args = (archive, manifest, [policy["pin"]], records, [policy["ids"][0][0]])
    with pytest.raises(backup.BackupRefused, match="erasure journal"):
        backup.restore(*args, tmp_path / "r1")
    old = tmp_path / "old.erasures.json"
    doc = json.loads(journal.read_bytes())
    body = {**doc["erasures"], "at": "2000-01-01T00:00:00Z"}
    old.write_bytes(backup._canon({"erasures": body, "signature": policy["key"].sign(
        backup.ERASURES_LABEL + backup._canon(body)).hex()}))
    with pytest.raises(backup.BackupRefused, match="older than the backup"):
        backup.restore(*args, tmp_path / "r2", old)
    forged = tmp_path / "forged.erasures.json"
    backup.write_erasures(tmp_path / "store", Ed25519PrivateKey.generate(), forged)
    with pytest.raises(backup.BackupRefused, match="not signed by a pinned"):
        backup.restore(*args, tmp_path / "r3", forged)
    assert not any((tmp_path / r).exists() for r in ("r1", "r2", "r3"))
    assert "visit" not in journal.read_text().replace("visits", "")  # ids only: no purpose, no plate, no name
