# SPDX-License-Identifier: EUPL-1.2
"""The signer rotates its records key (#41): the next history is written at its size, signed by the pinned trustees and
accepted by the new key; from then on only the new key signs, under its own origin, and a restart with the old key
signs nothing."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import records_keys as K
from keyclerk import trustees as T
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import note as N
from tests.test_records_keys import WITNESS, WNAME, WVKEY, hx, seal
from tests.test_signer_ha import _add, _trustees_pinned  # noqa: F401 - the autouse fixture
from tests.test_signer_replica import world  # noqa: F401 - the fixture
from tests.test_trustees import pinned_set

ORIGIN1, ORIGIN2 = "keyclerk.example/log-1", "keyclerk.example/log-2"


def cosigned(origin, store, key):
    text = N.checkpoint_text(origin, store.size(), store.root())
    return text + "\n" + N.sign(text, origin, key) + N.cosign(text, WNAME, WITNESS, 1_793_000_000)


@pytest.fixture
def pinned(world, monkeypatch):  # noqa: F811
    s = world["signer"]
    v1 = K.KeyHistory({"format": K.FORMAT, "realm": s.replica.realm, "version": 1, "trusted": None,
                       "reason_sha256": "0" * 64, "at": "2026-11-06T20:00:00Z",
                       "keys": [{"key": s.public_key(), "origin": ORIGIN1, "from_seq": 0, "to_seq": None}]})
    ts = pinned_set(s.replica.realm)
    monkeypatch.setattr(K, "pinned", lambda: v1)
    monkeypatch.setattr(T, "pinned", lambda: {"set": ts, "since": 0})
    return {"v1": v1, "ts": ts}


def rotated(world):  # noqa: F811
    s, new = world["signer"], Ed25519PrivateKey.generate()
    doc = s.rotation_statement(hx(new), ORIGIN2, cosigned(ORIGIN1, s.replica, world["key"]), WVKEY, "scheduled")
    return s, new, doc


def test_a_rotation_switches_the_signer_to_the_new_key_under_a_new_origin(world, pinned):  # noqa: F811
    s, new, doc = rotated(world)
    b = s.replica.size()
    out = s.rotate(seal(doc, new), new)
    assert out == {"version": 2, "switch": b, "origin": ORIGIN2}
    assert s.public_key() == hx(new) and s.genesis_key() == hx(world["key"])
    p = {"tmp": world["tmp"]}
    _add(p, s)                                                         # the first link the new key signs
    assert s.replica.size() == b + 1 and s.replica.pinned.key_at(b) == hx(new)
    assert [v["bytes"] for v in s.records_keys()["versions"]] == [seal(doc, new)["bytes"]]


def test_after_a_rotation_the_signer_starts_with_the_new_key_and_never_the_old(world, pinned):  # noqa: F811
    s, new, doc = rotated(world)
    s.rotate(seal(doc, new), new)
    state = s.state
    s.close()
    again = Signer(new, state)
    try:
        assert again.broken is None, again.broken                      # the audit chain follows the rotate line
    finally:
        again.close()
    old = Signer(world["key"], state)
    try:
        assert old.broken and "not the one records-key history version 2 has in force" in old.broken
    finally:
        old.close()
    world["signer"] = Signer(new, state)                               # the fixture closes what it holds


def test_a_rotation_without_the_trustees_or_with_another_key_is_refused(world, pinned, monkeypatch):  # noqa: F811
    s, new, doc = rotated(world)
    with pytest.raises(SignerRefused, match="the key given is not the history's new key"):
        s.rotate(seal(doc, new), Ed25519PrivateKey.generate())
    with pytest.raises(SignerRefused, match="does not hold"):
        s.rotate(seal(doc, new, who=("eva", "ingrid")), new)
    monkeypatch.setattr(T, "pinned", lambda: None)
    with pytest.raises(SignerRefused, match="no trustee set is pinned"):
        s.rotate(seal(doc, new), new)
    assert s.public_key() == hx(world["key"])                          # nothing changed


def test_a_history_that_switches_elsewhere_than_the_signers_size_is_refused(world, pinned):  # noqa: F811
    s, new, doc = rotated(world)
    _add({"tmp": world["tmp"]}, s)                                     # the log moved on after the statement
    with pytest.raises(SignerRefused, match="does not hold|switches at link"):
        s.rotate(seal(doc, new), new)


def test_the_ceremony_runs_through_the_command_line(world, pinned, tmp_path):  # noqa: F811
    """statement, two trustee signatures, seal (verified), rotate: as an operator runs it, the signer stopped."""
    import json
    from pathlib import Path

    from keyclerk import records_keys as RK
    from tests.test_trustees import KEYS
    s, old = world["signer"], world["key"]
    keyfile, newfile = tmp_path / "old.key", tmp_path / "new.key"
    keyfile.write_text(old.private_bytes_raw().hex(), encoding="utf-8")
    new = Ed25519PrivateKey.generate()
    newfile.write_text(new.private_bytes_raw().hex(), encoding="utf-8")
    notefile = tmp_path / "note"
    notefile.write_text(cosigned(ORIGIN1, s.replica, old), encoding="utf-8")
    state = s.state
    s.close()                                                          # one signer per state directory
    cfg = str(Path(__file__).resolve().parent / "fixtures" / "config.yaml")
    out = tmp_path / "next"
    assert RK.main(["statement", "--signer-state", str(state), "--key", str(keyfile), "--config", cfg,
                    "--new-public", hx(new), "--origin", ORIGIN2, "--note", str(notefile), "--witness", WVKEY,
                    "--reason", "scheduled", "--out", str(out)]) == 0
    tosign = out.with_suffix(".tosign").read_bytes()
    for tid in ("eva", "owner"):
        (tmp_path / f"{tid}.sig").write_text(KEYS[tid].sign(tosign).hex(), encoding="utf-8")
    (tmp_path / "v1.json").write_bytes(RK.canonical(pinned["v1"].doc))
    (tmp_path / "set.json").write_text(json.dumps(pinned["ts"]), encoding="utf-8")
    sealed = tmp_path / "sealed.json"
    assert RK.main(["seal", "--history", str(out.with_suffix(".json")), "--trustee-sig", f"eva={tmp_path / 'eva.sig'}",
                    "--trustee-sig", f"owner={tmp_path / 'owner.sig'}", "--new-key", str(newfile), "--out", str(sealed),
                    "--pinned", str(tmp_path / "v1.json"), "--trustees", str(tmp_path / "set.json")]) == 0
    assert RK.main(["verify", "--pinned", str(tmp_path / "v1.json"), "--trustees", str(tmp_path / "set.json"),
                    "--sealed", str(sealed), "--witness", WVKEY]) == 0
    assert RK.main(["rotate", "--signer-state", str(state), "--key", str(keyfile), "--new-key", str(newfile),
                    "--config", cfg, "--sealed", str(sealed)]) == 0
    world["signer"] = Signer(new, state)
    assert world["signer"].broken is None and world["signer"].public_key() == hx(new)


def test_a_backup_of_a_rotated_signer_verifies(world, pinned, tmp_path):  # noqa: F811
    """backup.verify checks each copied change log with its own records-key history and the audit chain across the
    rotate line (#41, F4)."""
    import shutil

    from keyclerk import backup
    s, new, doc = rotated(world)
    s.rotate(seal(doc, new), new)
    _add({"tmp": world["tmp"]}, s)
    state = s.state
    s.close()
    stage = tmp_path / "stage" / "signer"
    stage.mkdir(parents=True)
    for name in ("replica.db", "audit.jsonl"):
        shutil.copy2(state / name, stage / name)
    out = backup.verify(stage.parent, ["signer/replica.db", "signer/audit.jsonl"], hx(world["key"]))
    assert out["signer"]["full_check"] == "passed" and out["signer"]["audit_lines"] > 0
    world["signer"] = Signer(new, state)


def test_the_activity_log_never_takes_an_older_keys_line_after_a_newer_keys_line():
    """A desk's lines verify against the history's keys in order: the old key's lines before the rotation, never
    after the new key signed one (#41)."""
    from keyclerk.desk import DeskFiles
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    files = DeskFiles.__new__(DeskFiles)
    files._keys_cache = [old.public_key(), new.public_key()]

    def line(key, sha):
        return {"sha256": sha, "signature": key.sign(sha.encode()).hex()}
    assert files._signed(line(old, "a" * 64), 0) == 0
    assert files._signed(line(new, "b" * 64), 0) == 1
    assert files._signed(line(old, "c" * 64), 1) is None              # past the rotation the old key counts for nothing


def test_an_activity_log_rewritten_with_the_old_key_is_found(tmp_path):
    """Review N4: the desk's lines verify against its own store's verified history; once a newer key signed a line, a
    log rewritten whole with the older key is reported on the next full check."""
    import hashlib
    import json
    import time
    from types import SimpleNamespace

    from keyclerk import records_keys as RK
    from keyclerk.desk import DeskFiles
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    h = RK.KeyHistory({"format": RK.FORMAT, "realm": "example", "version": 2, "reason_sha256": "0" * 64,
                       "at": "2026-11-06T20:00:00Z", "trusted": {"note": "n", "witness": "w"},
                       "keys": [{"key": hx(old), "origin": ORIGIN1, "from_seq": 0, "to_seq": 3},
                                {"key": hx(new), "origin": ORIGIN2, "from_seq": 3, "to_seq": None}]})

    def write(keys):
        prev, out = "0" * 64, []
        for i, k in enumerate(keys):
            e = {"at": f"2026-11-06T20:0{i}:00Z", "prev": prev, "action": "t"}
            sha = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
            out.append(json.dumps({**e, "sha256": sha, "signature": k.sign(sha.encode()).hex()}, sort_keys=True))
            prev = sha
        (tmp_path / "log.jsonl").write_text("\n".join(out) + "\n", encoding="utf-8")

    files = DeskFiles.__new__(DeskFiles)
    files.path, files._pub = tmp_path, new.public_key()
    files.follower = SimpleNamespace(store=SimpleNamespace(pinned=h))
    files._verified = (0, "0" * 64, [], 0, time.monotonic())
    write([old, old, new])
    assert files.verify_log() == []
    write([old, old, old])                                             # the stolen old key rewrites the whole log
    files._verified = (0, "0" * 64, [], 0, time.monotonic())
    assert any("rewritten with an older key" in e for e in files.verify_log())
