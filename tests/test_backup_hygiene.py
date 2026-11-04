# SPDX-License-Identifier: EUPL-1.2
"""Decision 0019 point 2: the escrowed keys are shown to be still held, a retired key stays needed while a kept backup
was encrypted to it, and a recipient in use too long is due for rotation."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import age, backup

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def realm(tmp_path, monkeypatch):
    ids = [age.keygen() for _ in range(3)]                       # (identity, recipient): two custodians, one retired
    cur = [ids[0][1], ids[1][1]]
    policy = {"recipients": cur, "retention_days": 90}
    monkeypatch.setattr(backup, "_policy", lambda: policy)
    key = Ed25519PrivateKey.generate()
    m = tmp_path / "manifests"
    m.mkdir()

    def manifest(name, at, to):
        body = {"format": backup.FORMAT, "taken_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "recipients": to}
        (m / f"{name}.manifest.json").write_bytes(
            backup._canon({"manifest": body, "signature": key.sign(backup.LABEL + backup._canon(body)).hex()}))
    manifest("old", NOW - timedelta(days=400), [ids[2][1], ids[0][1]])     # aged out: the retired key's only other use
    manifest("kept", NOW - timedelta(days=30), [ids[2][1], ids[1][1]])    # kept: still needs the retired key
    manifest("new", NOW - timedelta(days=1), cur)
    return {"ids": ids, "key": key, "pins": [backup.public_hex(key)], "dir": m, "policy": policy}


def test_the_recipients_that_matter_include_a_retired_key_a_kept_backup_needs(realm):
    need = backup.needed_recipients(realm["dir"], realm["pins"], NOW)
    retired = realm["ids"][2][1]
    assert set(need) == {r for _, r in realm["ids"]}
    assert need[retired]["current"] is False and need[retired]["kept_backups"] == 1


def test_escrow_is_proven_by_decrypting_a_fresh_challenge(realm):
    d, pins, key = realm["dir"], realm["pins"], realm["key"]
    assert {f["kind"] for f in backup.hygiene(d, pins, NOW)["findings"]} == {"escrow_unproven", "rotate"}
    files = backup.escrow_challenge(d, pins, key)
    assert len(files) == 3
    (i0, r0), (i1, r1), (i2, r2) = realm["ids"]
    backup.escrow_answer(d, pins, key, r0, ids=[i0])                         # a host holding the identity
    read = age.decrypt((d / "escrow" / f"{backup._rid(r1)}.challenge.age").read_bytes(), [i1]).decode()
    backup.escrow_answer(d, pins, key, r1, answer=read)                     # a custodian with age -d
    with pytest.raises(backup.BackupRefused, match="does not open"):
        backup.escrow_answer(d, pins, key, r2, ids=[i0])                     # another key does not prove this one
    with pytest.raises(backup.BackupRefused, match="was not shown"):
        backup.escrow_answer(d, pins, key, r2, answer="0" * 32)
    unproven = [f["recipient"] for f in backup.hygiene(d, pins)["findings"] if f["kind"] == "escrow_unproven"]
    assert unproven == [r2]                                                  # the retired key is still needed
    backup.escrow_answer(d, pins, key, r2, ids=[i2])
    assert not [f for f in backup.hygiene(d, pins)["findings"] if f["kind"] == "escrow_unproven"]


def test_a_proof_expires_and_an_unsigned_one_does_not_count(realm):
    d, pins, key = realm["dir"], realm["pins"], realm["key"]
    backup.escrow_challenge(d, pins, key)
    for ident, r in realm["ids"]:
        backup.escrow_answer(d, pins, key, r, ids=[ident])
    later = datetime.now(timezone.utc) + timedelta(days=91)
    assert len([f for f in backup.hygiene(d, pins, later)["findings"] if f["kind"] == "escrow_unproven"]) >= 2
    other = [backup.public_hex(Ed25519PrivateKey.generate())]
    assert all(r["escrow_proven"] is None for r in backup.hygiene(d, other, NOW)["recipients"])


def test_a_recipient_in_use_past_the_rotation_age_is_due(realm):
    found = backup.hygiene(realm["dir"], realm["pins"], NOW)["findings"]
    due = [f["recipient"] for f in found if f["kind"] == "rotate"]
    assert due == [realm["ids"][0][1]]                                       # first used 400 days ago
    realm["policy"]["rotate_after_days"] = 500
    assert not [f for f in backup.hygiene(realm["dir"], realm["pins"], NOW)["findings"] if f["kind"] == "rotate"]


def test_the_command_line_says_findings_by_its_exit_code(realm, capsys):
    pin = realm["pins"][0]
    assert backup.main(["hygiene", "--manifests", str(realm["dir"]), "--pin", pin]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["findings"] and not out["ok"]
