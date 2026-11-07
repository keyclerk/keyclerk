# SPDX-License-Identifier: EUPL-1.2
"""The broker's high-water mark is signed by the reconciler: a mark that does not verify, or records behind it, refuse
the revision, but memberships the records never required are still removed and the run raises an incident; so whoever
can write the mark in the broker cannot freeze every removal (review 2026-10-26, E4)."""
from tests.test_reconcile import AT, MarkedBroker, args, doc, mark_key_file, mark_of, write

from keyclerk import reconcile as Rc

PLANTED = {(f"/grants/planted-{i}", f"idp:p{i}") for i in range(3)}


def _started(tmp_path):
    """A broker with one applied, signed revision, then intruders added by hand."""
    b, key = MarkedBroker(), mark_key_file(tmp_path)
    d = doc()
    d["revision"] = 5
    assert Rc.run_once(args(tmp_path, write(tmp_path, d, "r5.yaml"), mark_key=key), AT, b)["applied"]
    b.have |= PLANTED
    return b, key, d


def test_a_forged_mark_refuses_the_revision_but_intruders_still_go(tmp_path):
    b, key, d = _started(tmp_path)
    b.mark = "999999"                                            # someone with broker rights writes the mark
    d["revision"] = 6
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r6.yaml"), mark_key=key), AT, b)
    assert not run.get("applied") and "unsigned" in run["refused"]
    assert run["incident"]["kind"] == "high-water-mark" and run["alert"]
    assert run["intrusions_removed"] == 3 and not (PLANTED & b.have)


def test_a_mark_signed_by_another_key_does_not_verify(tmp_path):
    b, key, d = _started(tmp_path)
    other = mark_key_file(tmp_path, "other.key")
    b.mark = Rc.sign_mark(Rc.mark_key(args(tmp_path, "x", mark_key=other)), "example", 999999)
    d["revision"] = 6
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r6.yaml"), mark_key=key), AT, b)
    assert "does not verify" in run["refused"] and not (PLANTED & b.have)


def test_a_mark_for_another_realm_does_not_verify(tmp_path):
    b, key, d = _started(tmp_path)
    b.mark = Rc.sign_mark(Rc.mark_key(args(tmp_path, "x", mark_key=key)), "another-realm", 999999)
    d["revision"] = 6
    assert "does not verify" in Rc.run_once(args(tmp_path, write(tmp_path, d, "r6.yaml"), mark_key=key), AT, b)["refused"]


def test_older_records_behind_a_good_mark_still_remove_intruders(tmp_path):
    import shutil
    b, key, d = _started(tmp_path)
    shutil.rmtree(tmp_path / "state")                            # only the mark remembers revision 5 now
    unanchored = {("/grants/planted-x", "uid:0000aaaa-0001")}
    b.have |= unanchored
    d["revision"] = 4
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r4.yaml"), mark_key=key), AT, b)
    assert "older than revision 5" in run["refused"] and run["incident"]
    # with no accepted desired set left, an anchored member cannot be told from a lawful one: only members without
    # an anchor go, as on a first run
    assert not (unanchored & b.have) and PLANTED <= b.have
    assert mark_of(b) == 5                                       # the mark never moves on a refused revision


def test_a_marking_broker_needs_the_key(tmp_path):
    d = doc()
    d["revision"] = 1
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r1.yaml")), AT, MarkedBroker())
    assert "--mark-key" in run["refused"]


def test_an_upgrade_adopts_an_unsigned_mark_once_and_only_when_not_ahead(tmp_path):
    key = mark_key_file(tmp_path)
    d = doc()
    d["revision"] = 7
    b = MarkedBroker()
    b.mark = "9"                                                 # ahead of the records: never adopted
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r7.yaml"), mark_key=key, adopt_mark=True), AT, b)
    assert "unsigned" in run["refused"]
    b.mark = "6"                                                 # an earlier engine's mark, behind the records
    assert Rc.run_once(args(tmp_path, write(tmp_path, d, "r7.yaml"), mark_key=key, adopt_mark=True), AT, b)["applied"]
    assert b.mark.startswith("kc-mark-v1:7:")
    assert Rc.run_once(args(tmp_path, write(tmp_path, d, "r7.yaml"), mark_key=key), AT, b)["applied"]   # signed now


def test_f8_a_recovery_resets_what_a_stolen_key_pushed_forward(tmp_path, monkeypatch):
    """#41 F8 (TUF's fast-forward): after a recovery the last applied records from dropped links are no base, and a
    mark signed under the older history counts only to the switch; a mark under the new history names its version."""
    from types import SimpleNamespace

    from keyclerk.store import replay

    class Store:
        pinned = SimpleNamespace(version=2, switch=10)
    monkeypatch.setattr(replay, "revision_at", lambda st, size: 9 if size == 10 else None)
    last, hv, back, rec = Rc.recovery_base(Store(), 1, {"revision": 50})
    assert last is None and hv == 2 and back == 9 and rec["dropped_applied"] == 50
    assert Rc.recovery_base(Store(), 2, {"revision": 50})[0] == {"revision": 50}            # already applied under it
    assert Rc.recovery_base(Store(), 1, {"revision": 8})[0] == {"revision": 8}              # a planned rotation
    key = Rc.mark_key(args(tmp_path, "x", mark_key=mark_key_file(tmp_path)))
    v2 = Rc.sign_mark(key, "example", 12, 2)
    assert v2.startswith("kc-mark-v2:12:2:") and Rc.read_mark(v2, key, "example") == (12, None)
    assert Rc.mark_history(v2) == 2 and Rc.mark_history(Rc.sign_mark(key, "example", 12)) == 1
    assert Rc.sign_mark(key, "example", 12, 1).startswith("kc-mark-v1:12:")
    assert Rc.read_mark(v2.replace(":12:2:", ":12:3:"), key, "example")[1] is not None   # the version is signed
