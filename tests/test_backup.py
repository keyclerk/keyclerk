# SPDX-License-Identifier: EUPL-1.2
"""Backup, its manifest and the restore drill (decision 0019 points 1 to 4, issue 26): a backup taken while the desk
runs restores to a desk whose log verifies end to end; the manifest is checked before a restore starts, and a backup
that does not match it is refused with the reason; a backup never carries a key; a drill reports the recovery time."""
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_log_desk import ADD, ANN, started  # noqa: F401 - started is a fixture

from keyclerk import age, backup, restore
from keyclerk.desk import Desk
from keyclerk.signer import Signer
from keyclerk.store import replay as RP
from keyclerk.store.log_desk import LogStore


@pytest.fixture
def kit(started, monkeypatch):
    """Two custodians, a drill test key, this host's manifest key, and the recipients in the configuration."""
    from keyclerk import config
    a, b, test = age.keygen(), age.keygen(), age.keygen()
    key = Ed25519PrivateKey.generate()
    cfg = {**config.current(), "backup": {"recipients": [a[1], b[1], test[1]]}}
    monkeypatch.setattr(config, "current", lambda: cfg)
    return {**started, "custodians": [a, b], "test": test, "key": key, "pin": backup.public_hex(key),
            "records": started["signer"].public_key(), "out": started["tmp"] / "off-site", "cfg": cfg}


def _take(kit, **kw):
    return backup.take(kit["out"], kit["records"], kit["key"], desk=kit["tmp"] / "desk",
                       signer_state=kit["tmp"] / "signer", **kw)


def _j(manifest):
    """The erasure journal take wrote beside a manifest."""
    return manifest.with_name(manifest.name.removesuffix(".manifest.json") + ".erasures.json")


def test_a_backup_taken_while_the_desk_runs_restores_to_a_desk_whose_log_verifies(kit):
    Desk(kit["store"]).propose(ANN, ADD)
    live = kit["signer"].replica
    archive, manifest, body = _take(kit)                          # the desk and the signer keep running
    head, size = live.head(), live.size()
    assert body["revision"] == RP.revision(live) and body["head"] == head.hex()
    assert body["verified"]["signer"]["full_check"] == "passed" and body["verified"]["signer"]["audit_lines"] >= 0
    Desk(kit["store"]).propose(ANN, {**ADD, "anchor": "idp:44aa-dirk"})   # after the snapshot: not in it
    out = backup.restore(archive, manifest, [kit["pin"]], kit["records"], [kit["custodians"][1][0]],
                         kit["tmp"] / "restored", _j(manifest))
    assert out["revision"] == body["revision"]
    to = kit["tmp"] / "restored"
    assert restore.marker(to / "desk")                            # the restored desk starts in restore mode
    s = Signer(kit["signer"].key, to / "signer")
    try:
        assert not s.broken and s.replica.head() == head and s.replica.size() == size
        d = LogStore(to / "desk", s)
        try:
            RP.verify(d.store, kit["records"], d.store.realm)     # end to end, against the pinned key
            assert d.store.head() == head and not d.verify_log()
        finally:
            d.close()
    finally:
        s.close()


def test_a_backup_never_carries_a_key(kit):
    (kit["tmp"] / "desk" / "plate.key").write_text("ab" * 32)
    archive, manifest, body = _take(kit)
    names = {m["path"] for m in body["members"]}
    assert "desk/plate.key" not in names and "desk/plate.key" in body["keys_left_out"]
    assert not any(n.endswith((".lock", "-wal", "-shm")) for n in names)
    (kit["tmp"] / "desk" / "notes.txt").write_text("ab" * 32)     # a key under another name refuses the backup
    with pytest.raises(backup.BackupRefused, match="looks like a key"):
        _take(kit)


def test_a_backup_is_encrypted_only_to_the_configured_recipients(kit):
    """Decision 0029 point 2: the recipients are policy; a changed command line cannot add a reader."""
    _, _, body = _take(kit)
    assert body["recipients"] == kit["cfg"]["backup"]["recipients"]
    with pytest.raises(TypeError):
        _take(kit, recipients=[age.keygen()[1]])                  # there is no way to pass one
    kit["cfg"]["backup"]["recipients"] = [kit["custodians"][0][1]] * 2
    with pytest.raises(backup.BackupRefused, match="at least 2"):
        _take(kit)
    del kit["cfg"]["backup"]["recipients"]
    with pytest.raises(backup.BackupRefused, match="backup.recipients"):
        _take(kit)


def test_a_backup_against_another_records_key_is_refused(kit):
    other = Signer(Ed25519PrivateKey.generate(), kit["tmp"] / "elsewhere").public_key()
    with pytest.raises(backup.BackupRefused, match="another records key"):
        backup.take(kit["out"], other, kit["key"], desk=kit["tmp"] / "desk")


def test_a_backup_leaves_out_the_replicas_earlier_resyncs_replaced(kit):
    """Decision 0029 point 4: only the replica log.current names (or log.db) is backed up, verified."""
    import shutil
    desk = kit["tmp"] / "desk"
    shutil.copyfile(desk / "log.db", desk / "log-old.db")
    _, _, body = _take(kit)
    names = {m["path"] for m in body["members"]}
    assert "desk/log.db" in names and "desk/log-old.db" not in names


def test_a_log_line_still_being_written_waits_for_the_next_backup(kit):
    f = kit["tmp"] / "desk" / "log.jsonl"
    whole = f.read_bytes()
    f.write_bytes(whole + b'{"half": ')
    _, _, body = _take(kit)
    m = next(m for m in body["members"] if m["path"] == "desk/log.jsonl")
    assert m["bytes"] == len(whole)


@pytest.mark.parametrize("damage, why", [
    ("flip", "does not match its manifest's hash"),
    ("cut", "its manifest says"),
    ("manifest", "not signed by a pinned manifest key"),
    ("unpinned", "not signed by a pinned manifest key"),
])
def test_a_backup_that_does_not_match_its_manifest_is_refused_before_the_restore(kit, damage, why):
    archive, manifest, _ = _take(kit)
    pins = [kit["pin"]]
    if damage == "flip":
        b = bytearray(archive.read_bytes())
        b[len(b) // 2] ^= 1
        archive.write_bytes(bytes(b))
    elif damage == "cut":
        archive.write_bytes(archive.read_bytes()[:-1])
    elif damage == "manifest":
        doc = json.loads(manifest.read_bytes())
        doc["manifest"]["revision"] += 1
        manifest.write_text(json.dumps(doc))
    else:
        pins = [backup.public_hex(Ed25519PrivateKey.generate())]
    to = kit["tmp"] / "restored"
    with pytest.raises(backup.BackupRefused, match=why):
        backup.restore(archive, manifest, pins, kit["records"], [kit["custodians"][0][0]], to, _j(manifest))
    assert not to.exists()                                        # nothing was written


def test_a_restore_refuses_a_directory_that_is_not_empty_and_an_identity_it_was_not_made_for(kit):
    archive, manifest, _ = _take(kit)
    full = kit["tmp"] / "full"
    full.mkdir()
    (full / "x").write_text("x")
    with pytest.raises(backup.BackupRefused, match="not empty"):
        backup.restore(archive, manifest, [kit["pin"]], kit["records"], [kit["custodians"][0][0]], full, _j(manifest))
    with pytest.raises(backup.BackupRefused, match="does not decrypt"):
        backup.restore(archive, manifest, [kit["pin"]], kit["records"], [age.keygen()[0]], kit["tmp"] / "r2",
                       _j(manifest))


def test_a_drill_restores_the_newest_good_backup_and_reports_the_recovery_time(kit):
    _take(kit)
    Desk(kit["store"]).propose(ANN, ADD)
    _, _, newer = _take(kit)
    report = kit["tmp"] / "drills.jsonl"
    r = backup.drill(kit["out"], [kit["pin"]], kit["records"], [kit["test"][0]], report)
    assert r["ok"] and r["revision"] == newer["revision"] and r["recovery_seconds"] > 0
    assert json.loads(report.read_text().splitlines()[-1])["ok"]
    a = kit["out"] / newer["archive"]["name"]                     # the newest copy goes bad: an incident
    a.write_bytes(a.read_bytes()[:-1])
    r = backup.drill(kit["out"], [kit["pin"]], kit["records"], [kit["test"][0]], report)
    assert not r["ok"] and "incident" in r and "manifest says" in r["why"]


def test_backup_state_is_a_metric_that_ages_and_a_failed_drill_alerts(kit, monkeypatch):
    from keyclerk import config, health, metrics
    report = kit["tmp"] / "drills.jsonl"
    cfg = kit["cfg"]
    cfg["backup"] |= {"manifests": str(kit["out"]), "manifest_keys": [kit["pin"]], "drill_report": str(report)}
    metrics.reset()
    health._backup_gauges()

    def sample(name):
        rows = [ln for ln in metrics.render().splitlines() if ln.startswith(name + " ")]
        return float(rows[0].split()[1]) if rows else None
    assert sample("keyclerk_backup_age_seconds") is None                  # no backup yet: absent, never guessed
    _, manifest, _ = _take(kit)
    backup.drill(kit["out"], [kit["pin"]], kit["records"], [kit["test"][0]], report)
    assert sample("keyclerk_backup_age_seconds") is None                  # taken, not shipped: not off-site yet
    backup.shipped(manifest, "s3://backups/desk/" + manifest.name, kit["key"])
    assert 0 <= sample("keyclerk_backup_age_seconds") < 120
    assert sample("keyclerk_backup_drill_failed") == 0 and sample("keyclerk_backup_recovery_seconds") > 0
    cfg["backup"]["manifest_keys"] = [backup.public_hex(Ed25519PrivateKey.generate())]
    assert sample("keyclerk_backup_age_seconds") is None                  # a manifest no trusted key signed: none
    report.write_text(report.read_text() + json.dumps({"ok": False, "recovery_seconds": 1.0}) + "\n")
    assert sample("keyclerk_backup_drill_failed") == 1
    metrics.reset()


def test_a_shipped_record_counts_only_for_its_own_manifest_and_a_trusted_key(kit):
    """Decision 0019 point 3: where and when a backup was shipped is a signed fact beside its manifest."""
    _, manifest, _ = _take(kit)
    rec = backup.shipped(manifest, "s3://backups/desk/x", kit["key"])
    assert backup.read_shipped(manifest, [kit["pin"]])["where"] == "s3://backups/desk/x"
    assert backup.read_shipped(manifest, [backup.public_hex(Ed25519PrivateKey.generate())]) is None
    manifest.write_bytes(manifest.read_bytes() + b" ")             # the record names the manifest's exact bytes
    assert backup.read_shipped(manifest, [kit["pin"]]) is None
    assert rec.name.endswith(".shipped.json")
    with pytest.raises(backup.BackupRefused, match="one line"):
        backup.shipped(manifest, "a\nb", kit["key"])


def test_a_backup_streams_instead_of_holding_the_store_in_memory(kit):
    """Decision 0029 point 1: memory stays small whatever the size (the change log targets tens of thousands)."""
    import os
    import tracemalloc
    (kit["tmp"] / "desk" / "visits").mkdir(exist_ok=True)
    (kit["tmp"] / "desk" / "visits" / "big.bin").write_bytes(os.urandom(20 << 20))
    tracemalloc.start()
    try:
        archive, manifest, _ = _take(kit)
        backup.restore(archive, manifest, [kit["pin"]], kit["records"], [kit["test"][0]], kit["tmp"] / "restored",
                       _j(manifest))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert archive.stat().st_size > 20 << 20 and peak < 8 << 20, peak
