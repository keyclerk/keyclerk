# SPDX-License-Identifier: EUPL-1.2
"""The rollback witness (decision 0022 point 5, decision 0020 G10): a witness countersigns the change log's
checkpoints only along one history (c2sp.org/tlog-witness), and a signer restored from an older backup, mark and all,
stops when a witness proves it is behind or forked; an unsigned answer never stops it."""
import shutil
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - fixture

from keyclerk import witness as W
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import merkle
from keyclerk.store import note as N

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")

ORIGIN = "keyclerk.example/witness-test"


def _local(w):
    """A transport straight into a witness, as HTTP would carry it."""
    def t(method, url, body, timeout):
        return w.add_checkpoint(body) if method == "POST" else w.checkpoint(url.rsplit("/", 2)[-2])
    return t


def _witness(tmp_path, key, name="witness.example/w1"):
    return W.Witness(Ed25519PrivateKey.from_private_bytes(b"w" * 32) if name.endswith("w1") else
                     Ed25519PrivateKey.generate(), name, tmp_path / f"wstate-{name.rsplit('/', 1)[-1]}",
                     [N.vkey(ORIGIN, N.LOG, N.raw_public(key))])


def _with(signer, w, transport=None, **cfg):
    signer.configure_witness({"origin": ORIGIN, **cfg}, [W.Cosigner("http://w.invalid", w.vkey,
                                                                    transport=transport or _local(w))])
    return signer


def _propose(s, ops, cid):
    return s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
                     {"ops": ops, "entry": {"change_id": cid}}, [])


# --- the witness ---------------------------------------------------------------------------------------------------

def _tree(n, key):
    leaves = [merkle.leaf(f"link {i}".encode()) for i in range(n)]
    text = N.checkpoint_text(ORIGIN, n, merkle.mth(leaves))
    return leaves, text + "\n" + N.sign(text, ORIGIN, key)


def test_the_witness_countersigns_one_history_and_keeps_proof_of_another(tmp_path):
    key = Ed25519PrivateKey.generate()
    w = _witness(tmp_path, key)
    leaves, note3 = _tree(3, key)
    st, _, body = w.add_checkpoint(W.request_body(0, [], note3))
    assert st == 200 and N.verify(N.split(note3)[0], N.split(note3 + body.decode())[1], N.parse_vkey(w.vkey))
    leaves7, note7 = _tree(7, key)
    st, ctype, body = w.add_checkpoint(W.request_body(0, [], note7))               # a stale old size
    assert (st, ctype, body) == (409, W.SIZE_TYPE, b"3\n")
    st, _, _ = w.add_checkpoint(W.request_body(3, merkle.consistency(leaves7, 3), note7))
    assert st == 200
    other = [merkle.leaf(f"other {i}".encode()) for i in range(9)]                 # another history, same key
    text = N.checkpoint_text(ORIGIN, 9, merkle.mth(other))
    st, _, _ = w.add_checkpoint(W.request_body(7, merkle.consistency(other, 7), text + "\n" + N.sign(text, ORIGIN, key)))
    assert st == 422
    st, _, _ = w.add_checkpoint(W.request_body(3, [], note3))                     # behind what it countersigned
    assert st == 409
    kinds = [line.split('"kind": "')[1].split('"')[0] for line in (w.state / "evidence.jsonl").read_text().splitlines()]
    assert kinds == ["inconsistent", "behind"]
    again = W.Witness(w.key, w.name, w.state, [N.vkey(ORIGIN, N.LOG, N.raw_public(key))])   # after a restart
    st, _, body = again.checkpoint(W.origin_hash(ORIGIN))
    t, sigs = N.split(body.decode())
    assert st == 200 and N.parse_checkpoint(t)[1] == 7
    assert N.verify(t, sigs, (ORIGIN, N.LOG, N.raw_public(key))) == 0 and N.verify(t, sigs, N.parse_vkey(w.vkey))


def test_the_witness_refuses_unknown_logs_bad_signatures_and_bad_requests(tmp_path):
    key = Ed25519PrivateKey.generate()
    w = _witness(tmp_path, key)
    _, note = _tree(2, key)
    assert w.add_checkpoint(W.request_body(0, [], note.replace(ORIGIN, "keyclerk.example/other")))[0] == 404
    _, forged = _tree(2, Ed25519PrivateKey.generate())
    assert w.add_checkpoint(W.request_body(0, [], forged))[0] == 403                # another key, the log's name
    text, sigs = N.split(note)
    bad = text + "\n" + "".join(f"{N.DASH} {n} {N.b64(r[:-1] + bytes([r[-1] ^ 1]))}\n" for n, r in sigs)
    assert w.add_checkpoint(W.request_body(0, [], bad))[0] == 403                   # the log's key, a bad signature
    assert w.add_checkpoint(W.request_body(0, [merkle.leaf(b"x")], note))[0] == 422  # a proof from nothing
    assert w.add_checkpoint(W.request_body(5, [], note))[0] == 400                  # old above the size
    assert w.add_checkpoint(b"old 00\n\n" + note.encode())[0] == 400
    assert w.add_checkpoint(b"x" * (W.MAX_BODY + 1))[0] == 400


def test_the_witness_answers_over_http(tmp_path, world):
    w = _witness(tmp_path, world["key"])
    srv = W.serve(w, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        s = world["signer"]
        s.configure_witness({"origin": ORIGIN}, [W.Cosigner(f"http://127.0.0.1:{srv.server_address[1]}", w.vkey)])
        out = s.witness_check()
        assert out[w.name]["result"] == "cosigned" and s.head()["witness"]["size"] == s.replica.size()
    finally:
        srv.shutdown()
        srv.server_close()


# --- the signer ----------------------------------------------------------------------------------------------------

def test_a_change_is_witnessed_and_head_says_how_far(world, tmp_path):
    s = _with(world["signer"], _witness(tmp_path, world["key"]))
    assert s.head()["witness"]["unwitnessed_since"] is not None                    # nothing sent yet
    s.witness_check()
    _propose(s, change_ops(tmp_path, ADD, world), "C-w1")
    h = s.head()["witness"]
    assert h["size"] == s.replica.size() - 1 and h["unwitnessed_since"] and not h["incident"]
    assert s._witness_due.is_set()                                                 # the new head is due
    s.witness_check()
    h = s.head()["witness"]
    assert h["size"] == s.replica.size() and h["unwitnessed_since"] is None


def _restored(world, tmp_path):
    """The A5 scenario: the signer's state backed up, a change signed and witnessed, then the backup restored, its
    rollback mark with it. Returns the restored signer, the witness, and the ops of a change."""
    s, w = world["signer"], _witness(tmp_path, world["key"])
    ops = change_ops(tmp_path, ADD, world)
    _with(s, w).witness_check()
    s.close()
    shutil.copytree(s.state, tmp_path / "backup")
    s1 = _with(Signer(world["key"], s.state), w)
    _propose(s1, ops, "C-lost")
    assert s1.witness_check()[w.name]["result"] == "cosigned"
    s1.close()
    restored = Signer(world["key"], tmp_path / "backup")
    assert restored.broken is None                                                 # what 0.26.x had: it signs on
    world["signer"] = restored                                                     # the fixture closes this one
    return restored, w, ops


def test_a_signer_restored_from_an_older_backup_stops_when_the_witness_proves_it(world, tmp_path):
    s, w, ops = _restored(world, tmp_path)
    out = _with(s, w).witness_check()[w.name]
    assert out["result"] == "rolled_back" and out["size"] == s.replica.size() + 1
    assert "countersigned" in s.broken and "keyclerk.witness reset" in s.broken
    with pytest.raises(SignerRefused, match="countersigned"):
        _propose(s, ops, "C-second-history")
    assert s.head() == {"broken": s.broken}


def test_a_restored_signer_that_signed_again_is_caught_as_a_fork(world, tmp_path):
    s, w, ops = _restored(world, tmp_path)
    _propose(s, ops, "C-second-history")                                          # before any witness check
    out = _with(s, w).witness_check()[w.name]
    assert out["result"] == "forked" and "another history" in s.broken
    with pytest.raises(SignerRefused):
        _propose(s, ops, "C-third")


def test_an_unsigned_answer_never_stops_signing(world, tmp_path):
    s = world["signer"]
    w = _witness(tmp_path, world["key"])

    def liar(method, url, body, timeout):        # on the path: a large size, and no checkpoint to back it
        return (409, W.SIZE_TYPE, b"999999\n") if method == "POST" else (404, "text/plain", b"")
    out = _with(s, w, transport=liar).witness_check()[w.name]
    assert out["result"] == "error" and s.broken is None
    assert "not served" in s.head()["witness"]["cosigners"][w.name]["error"]
    other = W.Witness(Ed25519PrivateKey.generate(), w.name, tmp_path / "impostor",       # its name, not its key
                      [N.vkey(ORIGIN, N.LOG, N.raw_public(world["key"]))])
    out = _with(s, w, transport=_local(other)).witness_check()[w.name]
    assert out["result"] == "error" and "without its cosignature" in out["why"] and s.broken is None


def test_an_unreachable_witness_is_an_incident_and_blocks_only_by_policy(world, tmp_path):
    s, w = world["signer"], _witness(tmp_path, world["key"])

    def down(*a):
        raise OSError("connection refused")
    _with(s, w, transport=down, incident_after_minutes=0).witness_check()
    h = s.head()["witness"]
    assert h["incident"] and not h["blocking"] and "did not answer" in h["cosigners"][w.name]["error"]
    _propose(s, change_ops(tmp_path, ADD, world), "C-ddil")                         # a cut-off site goes on
    _with(s, w, transport=down, block_after_minutes=0)
    with pytest.raises(SignerRefused, match="not been witnessed"):
        _propose(s, change_ops(tmp_path, ADD, world), "C-blocked")


def test_after_the_witness_owner_resets_the_log_the_restored_signer_is_witnessed_again(world, tmp_path):
    s, w, _ = _restored(world, tmp_path)
    _with(s, w).witness_check()
    assert s.broken
    s.close()
    assert W.main(["reset", "--state", str(w.state), "--origin", ORIGIN, "--by", "witness-owner",
                   "--reason", "restore confirmed by the realm's officers"]) == 0
    assert '"kind": "reset"' in (w.state / "evidence.jsonl").read_text()
    again = _with(Signer(world["key"], tmp_path / "backup"), w)
    world["signer"] = again
    out = again.witness_check()[w.name]
    assert out["result"] == "cosigned" and again.broken is None, out


def test_a_quorum_counts_only_checkpoints_enough_witnesses_hold(world, tmp_path):
    s = world["signer"]
    w1, w2 = _witness(tmp_path, world["key"]), _witness(tmp_path, world["key"], "witness.example/w2")

    def down(*a):
        raise OSError("unreachable")
    s.configure_witness({"origin": ORIGIN, "quorum": 2}, [W.Cosigner("http://a.invalid", w1.vkey, transport=_local(w1)),
                                                          W.Cosigner("http://b.invalid", w2.vkey, transport=down)])
    s.witness_check()
    h = s.head()["witness"]
    assert h["cosigners"][w1.name]["size"] == s.replica.size() and h["size"] == 0 and h["unwitnessed_since"]


def test_the_witness_configuration_is_checked_across_its_fields():
    from keyclerk import config
    cos = N.vkey("witness.example/c", N.COSIGNATURE, N.raw_public(Ed25519PrivateKey.generate()))
    log = N.vkey("witness.example/l", N.LOG, N.raw_public(Ed25519PrivateKey.generate()))
    name, kid, rest = cos.split("+", 2)
    wrong_id = f"{name}+{'0' * 8 if kid != '0' * 8 else '1' * 8}+{rest}"

    def errs(**w):
        return config.validate({**config.current(), "witness": {"origin": ORIGIN, **w}})

    def one(vkey):
        return [{"url": "https://w.example", "vkey": vkey}]
    assert errs(cosigners=one(cos)) == []
    assert any("kc-" in e for e in errs(cosigners=one(cos), origin="kc-log"))
    assert any("log key" in e for e in errs(cosigners=one(log)))
    assert any("quorum" in e for e in errs(cosigners=one(cos), quorum=2))
    assert any("key id" in e for e in errs(cosigners=one(wrong_id)))
    assert any("one name" in e for e in errs(cosigners=one(cos) + one(cos)))
