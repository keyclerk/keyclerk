"""Decision 0022 S3: the checking signer keeps its own replica, built only from links it signed (never state from the
desk), checks a
proposed change there, and only then signs it with its checkpoint; the desk follows and resyncs, never signs."""
import json
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk.desk import Desk, Store
from keyclerk.signer import Signer, SignerClient, SignerRefused, serve
from keyclerk.store import link as L, migrate as M, replay as RP
from keyclerk.store.follow import Follower
from keyclerk.store.memory import MemoryStore

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ANN = {"anchor": "idp:7c1f-ann", "roles": []}
TOKEN = "eyJ.a-broker-token.sig"


def _keyfile(path, key):
    path.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return path


@pytest.fixture
def world(tmp_path):
    """A signer that signed the fixture as revision 1 (the YAML path of 0015), then migrated its own state."""
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer-state")
    desk = Store(tmp_path / "desk", None, FIXTURES / "records.yaml", signer=signer)
    desk.close()
    head = signer.migrate()
    assert signer.config_pending                       # in full until a background full check passes
    signer.background_check()
    assert not signer.config_pending
    yield {"key": key, "signer": signer, "tmp": tmp_path, "head": head}
    signer.close()


def change_ops(tmp_path, action, world=None):
    """The ops of a change the desk would make, from a scratch desk with its own key (realistic records); with world,
    re-keyed through the signer replica's mapping (decision 0028), as the desk on the store will propose them."""
    scratch = tmp_path / f"scratch-{len(list(tmp_path.glob('scratch-*')))}"
    k = _keyfile(tmp_path / f"{scratch.name}.key", Ed25519PrivateKey.generate())
    d = Desk(Store(scratch, k, FIXTURES / "records.yaml"))
    before = d.store.load()
    assert d.propose(ANN, action)["outcome"] == "applied"
    after = d.store.load()
    d.store.close()
    _, old, _ = M.split(before)
    _, new, _ = M.split(after)
    old = {(o["kind"], o["key"]): o["record"] for o in old}
    ops = [o for o in new if old.get((o["kind"], o["key"])) != o["record"]]
    return internal(ops, world["signer"].replica) if world else ops


def internal(ops, store):
    """Ops with their records' anchors re-keyed through a store's mapping rows."""
    from keyclerk import anchors as A
    amap = {r["idp"]: r["anchor"] for _, r in store.side_scan("anchor_map")}
    return [{**o, "record": A.rekey({o["kind"]: [o["record"]]}, amap)[o["kind"]][0]} for o in ops]


def _ann(signer):
    """Ann's internal anchor in a migrated replica (decision 0028)."""
    from keyclerk import anchors as A
    return A.inward(signer.replica, "idp:7c1f-ann")


ADD = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5}


# --- the signer's own state --------------------------------------------------------------------------------------------

def test_the_signer_migrates_its_own_last_revision_and_refuses_yaml_commits_after(world):
    s = world["signer"]
    assert world["head"]["migration"] == "proven" and world["head"]["revision"] == 1
    assert RP.records(s.replica)["revision"] == 1
    with pytest.raises(SignerRefused, match="keeps the change log since revision 1: propose changes"):
        s.commit("realm: example\n", {"records_sha256": "0" * 64, "revision": 2})
    with pytest.raises(SignerRefused, match="migrates once"):
        s.migrate()


def test_a_change_is_signed_only_after_the_replica_checks_it(world, tmp_path):
    s = world["signer"]
    ops = change_ops(tmp_path, ADD, world)
    assert [o["kind"] for o in ops] == ["memberships"]
    base = {"size": s.replica.size(), "head": s.replica.head().hex()}
    answer = s.propose(base, {"ops": ops, "entry": {"action": "add_member", "actor": "idp:7c1f-ann"}}, [])
    assert answer["revision"] == 2 and answer["hash"] == s.replica.head().hex()
    assert L.check_checkpoint(answer["checkpoint"], s.public_key(), "example", s.replica.size(), s.replica.root(),
                              s.replica.head())
    assert json.loads((s.state / "log-mark.json").read_text())["size"] == s.replica.size()


def test_r1_a_desk_that_lies_about_state_gets_no_signature(world, tmp_path):
    """The desk's word is never state: whatever it claims, the change is checked against the signer's own replica."""
    s = world["signer"]
    good = {"size": s.replica.size(), "head": s.replica.head().hex()}
    before = (s.replica.size(), s.replica.root())
    ops = change_ops(tmp_path, ADD, world)
    ghost = [{**ops[0], "record": {**ops[0]["record"], "group": "a-group-only-the-desk-has"}}]
    with pytest.raises(SignerRefused, match="the engine's checks refuse it"):
        s.propose(good, {"ops": ghost, "entry": {"action": "add_member"}}, [])
    first = next(k for k, _ in s.replica.scan("memberships"))
    with pytest.raises(SignerRefused, match="history rewritten"):
        s.propose(good, {"ops": [{"op": "del", "kind": "memberships", "key": first}], "entry": {}}, [])
    with pytest.raises(SignerRefused, match="stale: the signer's head is"):
        s.propose({"size": 7, "head": "ab" * 32}, {"ops": ops, "entry": {}}, [])
    with pytest.raises(SignerRefused, match="not a change the log can carry"):
        s.propose(good, {"ops": [{"op": "put", "kind": "visits", "key": "V-1", "record": {"visit_id": "V-1"}}],
                         "entry": {}}, [])
    with pytest.raises(SignerRefused, match="a token for no proof this change puts"):
        import hashlib
        s.propose(good, {"ops": ops, "entry": {}}, [[hashlib.sha256(TOKEN.encode()).hexdigest(), TOKEN]])
    assert (s.replica.size(), s.replica.root()) == before            # nothing was kept
    s.propose(good, {"ops": ops, "entry": {"action": "add_member"}}, [])  # and the honest change still applies


def test_proof_tokens_go_to_the_replica_side_and_are_read_out_only_with_an_audit_line(world, tmp_path):
    s = world["signer"]
    ann = _ann(s)
    proof = L.proof_record({"records": ["M-example-0001"], "by": ann, "token": TOKEN})
    op = {"op": "put", "kind": "approval_proofs", "key": proof["sha256"], "record": proof}
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": [op], "entry": {}},
              [[proof["sha256"], TOKEN]])
    assert RP.records(s.replica)["approval_proofs"] == [{"records": ["M-example-0001"], "by": ann, "token": TOKEN}]
    assert s.tokens(None, 10) == {"tokens": [[proof["sha256"], TOKEN]]}
    with pytest.raises(SignerRefused, match="limit 1 to 500"):
        s.tokens(None, 501)
    line = json.loads((s.state / "audit.jsonl").read_text().splitlines()[-1])
    assert line["op"] == "tokens" and line["count"] == 1 and len(line["signature"]) == 128


# --- the desk follows ------------------------------------------------------------------------------------------------

def _follower(world, n=[0]):  # noqa: B006 - a counter shared across calls, on purpose
    s = world["signer"]

    def fresh():
        n[0] += 1
        return MemoryStore(s.public_key(), "example")
    f = Follower(fresh(), s, fresh)
    f.catch_up()
    return f


def test_a_desk_follows_and_reaches_the_signers_head(world, tmp_path):
    f = _follower(world)
    s = world["signer"]
    assert f.store.head() == s.replica.head() and f.store.root() == s.replica.root()
    f.propose({"ops": change_ops(tmp_path, ADD, world), "entry": {"action": "add_member"}})
    assert f.alarms == [] and f.store.head() == s.replica.head()
    assert RP.records(f.store)["revision"] == 2 and f.store.migration() == "not re-provable: the YAML bytes were erased"


def test_a_desk_that_lost_its_store_or_fell_behind_resyncs(world, tmp_path):
    s = world["signer"]
    f = _follower(world)
    ops = change_ops(tmp_path, ADD, world)
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": ops, "entry": {}}, [])   # missed
    proof = L.proof_record({"records": ["M-example-0001"], "by": _ann(world["signer"]), "token": TOKEN})
    second = [{"op": "put", "kind": "approval_proofs", "key": proof["sha256"], "record": proof}]
    answer = s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": second, "entry": {}},
                       [[proof["sha256"], TOKEN]])
    f.apply(answer, [[proof["sha256"], TOKEN]])           # a link the desk's store cannot follow: alarm, resync
    assert f.alarms and "refused the signer's link" in f.alarms[0]
    assert f.store.head() == s.replica.head() and RP.records(f.store) == RP.records(s.replica)   # tokens came too
    f.store = MemoryStore(s.public_key(), "example")      # the store is gone altogether
    f.resync()
    assert f.store.root() == s.replica.root()


# --- one signer, a verified replica -------------------------------------------------------------------------------------

def test_a_second_signer_on_the_same_state_is_refused(world):
    with pytest.raises(SignerRefused, match="another signer holds .*one signer per state directory"):
        Signer(world["key"], world["signer"].state)


def test_a_replica_that_fails_verification_refuses_to_sign(world, tmp_path):
    s = world["signer"]
    s.close()
    db = sqlite3.connect(s.state / "replica.db")
    db.execute("UPDATE links SET signature = ? WHERE seq = 1", ("00" * 64,))
    db.commit()
    db.close()
    again = Signer(world["key"], s.state)
    assert again.broken and "failed verification" in again.broken and "restore the signer's state" in again.broken
    with pytest.raises(SignerRefused, match="failed verification"):
        again.propose({"size": 0, "head": None}, {"ops": [], "entry": {}}, [])
    assert again.head() == {"broken": again.broken}
    world["signer"] = again


def test_a_replica_restored_from_an_older_backup_refuses_to_sign(world, tmp_path):
    s = world["signer"]
    s.close()
    backup = tmp_path / "backup"
    backup.mkdir()
    shutil.copy(s.state / "replica.db", backup / "replica.db")
    s = Signer(world["key"], s.state)
    world["signer"] = s                                  # change_ops re-keys through the reopened replica
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {}}, [])
    s.close()
    for suffix in ("-wal", "-shm"):
        (s.state / f"replica.db{suffix}").unlink(missing_ok=True)
    shutil.copy(backup / "replica.db", s.state / "replica.db")
    again = Signer(world["key"], s.state)
    assert again.broken and "restored from an older backup must not sign on top of a newer history" in again.broken
    world["signer"] = again


# --- over the socket ---------------------------------------------------------------------------------------------------

def test_the_new_ops_over_the_socket(world, tmp_path):
    s = world["signer"]
    srv = serve(s, "tcp:127.0.0.1:0", "t0ken-for-tests")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        tok = tmp_path / "token"
        tok.write_text("t0ken-for-tests", encoding="utf-8")
        c = SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(tok))
        h = c.head()
        assert h["size"] == s.replica.size() and h["migration"] == "proven"
        answer = c.propose({"size": h["size"], "head": h["head"]}, {"ops": change_ops(tmp_path, ADD, world), "entry": {}})
        assert answer["revision"] == 2
        assert len(c.links(0, 500)["links"]) == s.replica.size()
        assert c.checkpoint()["checkpoint"] == s.replica.checkpoint()
        with pytest.raises(SignerRefused, match="stale"):
            c.propose({"size": h["size"], "head": h["head"]}, {"ops": [], "entry": {}})
        c.ping()
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_desk_store_migrates_through_the_signer(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer-state")
    try:
        Store(tmp_path / "desk", None, FIXTURES / "records.yaml", signer=signer).close()
        got = M.migrate_desk_store(tmp_path / "desk", tmp_path / "desk.db", signer=signer)
        assert got["migration"] == "proven" and got["revision"] == 1
        assert signer.head()["head"] == signer.replica.head().hex()
        with pytest.raises(Exception, match="exists"):
            M.migrate_desk_store(tmp_path / "desk", tmp_path / "desk.db", signer=signer)
    finally:
        signer.close()


class SpyKey:
    """The records key, with every message it signs written down."""

    def __init__(self, key):
        self.key, self.signed = key, []

    def sign(self, data):
        self.signed.append(data)
        return self.key.sign(data)

    def public_key(self):
        return self.key.public_key()


def test_the_key_signs_nothing_for_a_refused_change(world, tmp_path):
    """The S3 review's finding: a refused change never has a signature, not even one discarded in-process (a signed link
    with the right seq, prev and fence would be valid chain material if it ever left)."""
    import re
    s = world["signer"]
    s.key = spy = SpyKey(world["key"])
    good = {"size": s.replica.size(), "head": s.replica.head().hex()}
    ops = change_ops(tmp_path, ADD, world)
    ghost = [{**ops[0], "record": {**ops[0]["record"], "group": "a-group-only-the-desk-has"}}]
    first = next(k for k, _ in s.replica.scan("memberships"))
    for bad in ({"ops": ghost, "entry": {}}, {"ops": [{"op": "del", "kind": "memberships", "key": first}], "entry": {}}):
        with pytest.raises(SignerRefused) as e:
            s.propose(good, bad, [])
        assert not re.search(r"[0-9a-f]{128}", str(e.value))
    assert spy.signed == []
    s.propose(good, {"ops": ops, "entry": {}}, [])
    assert [m.split(b"\n", 1)[0] for m in spy.signed] == [b"kc-change-link-v1", b"kc-checkpoint-v1"]


def test_a_tampered_audit_log_refuses_to_sign_and_a_cut_line_is_set_aside(world):
    s = world["signer"]
    s.tokens(None, 10)
    s.tokens(None, 10)
    s.close()
    f = s.state / "audit.jsonl"
    lines = f.read_text().splitlines()
    f.write_text(lines[0] + "\n" + lines[1] + "\n" + '{"cut": ', encoding="utf-8")       # a crash mid-append
    again = Signer(world["key"], s.state)
    assert again.broken is None and len(f.read_text().splitlines()) == 2
    assert list(s.state.glob("audit.jsonl.partial-*"))
    again.close()
    f.write_text(lines[1].replace('"count": 0', '"count": 9') + "\n", encoding="utf-8")   # a line rewritten
    third = Signer(world["key"], s.state)
    assert third.broken and "audit log does not verify at line 1" in third.broken
    world["signer"] = third


def test_scoped_and_full_checks_give_the_signer_the_same_verdicts_and_fallbacks_are_counted(world, tmp_path):
    """Decision 0022 S4: the signer judges a change scoped to what it reaches; --full-check is the reference path."""
    from keyclerk import metrics
    s = world["signer"]
    ops = change_ops(tmp_path, ADD, world)
    ghost = [{**ops[0], "record": {**ops[0]["record"], "group": "a-group-only-the-desk-has"}}]
    first = next(k for k, _ in s.replica.scan("memberships"))
    refused = ({"ops": ghost, "entry": {}}, {"ops": [{"op": "del", "kind": "memberships", "key": first}], "entry": {}})
    for full in (False, True):
        s.full_check = full
        for change in refused:
            with pytest.raises(SignerRefused):
                s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, change, [])
    s.full_check = False
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": ops, "entry": {}}, [])
    before = dict(metrics._counters)
    g = s.replica.get("groups", "office-staff")
    tree = [{"op": "put", "kind": "groups", "key": "office-staff", "record": {**g, "parent": "all"}}]
    try:
        s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": tree, "entry": {}}, [])
    except SignerRefused:
        pass                                              # either way, it was judged in full
    key = ("keyclerk_check_fallback_total", (("reason", "group_tree"),))
    assert metrics._counters.get(key, 0) == before.get(key, 0) + 1


def test_a_plain_change_is_judged_on_the_working_set_without_a_fallback(world, tmp_path):
    from keyclerk import metrics
    s = world["signer"]
    before = sum(v for k, v in metrics._counters.items() if k[0] == "keyclerk_check_fallback_total")
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {}}, [])
    assert sum(v for k, v in metrics._counters.items() if k[0] == "keyclerk_check_fallback_total") == before
