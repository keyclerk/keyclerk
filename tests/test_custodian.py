# SPDX-License-Identifier: EUPL-1.2
"""The key custodian (decision 0033, #40): keyclerk-custodian holds the records key and refuses, on its own state
alone, anything that would break the change log's structure, whatever the signer asks. These tests build it with the
local Go toolchain (skipped without one) and run the checking signer on it. The attacks of the 2026-11-07 review are
held in cmd/keyclerk-custodian/regress_test.go; these tests hold the command line and the protocol from Python."""
import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import edge as E
from keyclerk.custodian import CustodianKey, CustodianRefused
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store import note as N

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
EXE = "keyclerk-custodian.exe" if sys.platform == "win32" else "keyclerk-custodian"
ORIGIN = "keyclerk.example/log-1"


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("no Go toolchain: the custodian is built with it")
    out = tmp_path_factory.mktemp("custodian-bin") / EXE
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off", "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-o", str(out), "."], cwd=ROOT / "cmd" / "keyclerk-custodian", check=True, env=env,
                   capture_output=True)
    return out


def keyfile(path: Path, key: Ed25519PrivateKey) -> Path:
    path.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    return path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(binary, *args) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=30)


class Custodian:
    """One custodian over loopback TCP, with its token; unwitnessed unless a witness is given."""

    def __init__(self, binary, state: Path, key: Path, realm="example"):
        self.binary, self.state, self.key, self.realm = binary, state, key, realm
        self.token = secrets.token_hex(16)
        self.tokfile = state.parent / f"{state.name}.token"
        self.tokfile.write_text(self.token, encoding="utf-8")
        self.addr = f"tcp:127.0.0.1:{free_port()}"
        self.proc = None

    def args(self, *extra):
        return [str(self.binary), "serve", "--state", str(self.state), "--realm", self.realm, "--key", str(self.key),
                "--listen", self.addr, "--token-file", str(self.tokfile), *extra]

    def start(self, *extra):
        self.proc = subprocess.Popen(self.args(*(extra or ("--unwitnessed",))), stderr=subprocess.PIPE, text=True)
        line = self.proc.stderr.readline()
        if "listening" not in line:
            self.proc.wait(10)
            raise RuntimeError(line + self.proc.stderr.read())
        return CustodianKey(self.addr, self.token)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)


def init(binary, state: Path, kf: Path, origin=ORIGIN):
    out = run(binary, "init", "--state", str(state), "--realm", "example", "--origin", origin, "--key", str(kf))
    assert out.returncode == 0, out.stderr


@pytest.fixture
def custodian(binary, tmp_path):
    key = Ed25519PrivateKey.generate()
    kf = keyfile(tmp_path / "records.key", key)
    init(binary, tmp_path / "cust", kf)
    c = Custodian(binary, tmp_path / "cust", kf)
    yield c, c.start(), key
    c.stop()


def link_body(seq, prev, fence=1, realm="example", at="2026-11-07T12:00:00Z"):
    return L.link_body(realm, seq, prev, fence, at,
                       [{"op": "put", "kind": "head", "key": "realm", "record": {"value": realm}}],
                       {"change_id": "C-0123456789ab", "action": "x", "actor": None, "outcome": "applied",
                        "records": {}})


def message(body):
    return L._message(L.LINK_FORMAT, E.canonical(body))


def sealed(ck, seq, prev, at="2026-11-07T12:00:00Z"):
    raw = E.canonical(link_body(seq, prev, at=at))
    sig = ck.sign(L._message(L.LINK_FORMAT, raw))
    return {"bytes": base64.b64encode(raw).decode(), "signature": sig.hex()}


def chain(ck, links, n, at="2026-11-07T12:00:00Z"):
    for _ in range(n):
        prev = merkle.leaf(L._message(L.LINK_FORMAT, base64.b64decode(links[-1]["bytes"])) +
                           bytes.fromhex(links[-1]["signature"])).hex() if links else L.ZERO
        links.append(sealed(ck, len(links), prev, at))
    return links


def migrated(tmp_path, key):
    """A log migrated by a signer holding the key itself (the one-time migration signs the YAML revision, which a
    custodian never does), and the log's links, size, root and head."""
    from keyclerk.desk import Store
    from keyclerk.signer import Signer
    signer = Signer(key, tmp_path / "signer")
    Store(tmp_path / "seed", None, FIXTURES / "records.yaml", signer=signer).close()
    signer.migrate()
    links = tmp_path / "links.jsonl"
    links.write_text("".join(json.dumps(signer.replica.link(i)) + "\n" for i in range(signer.replica.size())))
    out = (links, signer.replica.size(), signer.replica.root().hex(), signer.replica.head().hex())
    signer.close()
    return out


def ceremony(tmp_path, size, root, head):
    """The pinned trustee set, a kc-custodian-recovery-v1 statement and three trustees' signatures over it."""
    from test_trustees import KEYS, sign, trustee

    from keyclerk import trustees as T
    ts = {"format": T.FORMAT, "realm": "example", "version": 1, "at": "2026-11-06T19:00:00Z", "trustees": [
        trustee("eva", "idp:55bb-eva", "officer", KEYS["eva"], "sk-ssh-ed25519"),
        trustee("ingrid", "idp:31ee-ingrid", "officer", KEYS["ingrid"], "ssh-ed25519"),
        trustee("owner", "idp:2b9e-owner", "root", KEYS["owner"], "ed25519"),
        trustee("olga", "idp:88ee-olga", "root", KEYS["olga"], "sk-ssh-ed25519")]}
    (tmp_path / "set.json").write_text(json.dumps(ts))
    stmt = E.canonical({"format": "kc-custodian-recovery-v1", "realm": "example", "origin": ORIGIN, "size": size,
                        "root": root, "head": head, "at": "2026-11-07T12:00:00Z"})
    (tmp_path / "stmt.json").write_bytes(stmt)
    for who, kind in (("eva", "sk-ssh-ed25519"), ("owner", "ed25519"), ("ingrid", "ssh-ed25519")):
        (tmp_path / f"{who}.sig").write_text(sign(who, kind, label="kc-custodian-recovery-v1", body=stmt)["sig"])
    return stmt


def recover_args(tmp_path, links, kf):
    return ["recover", "--state", str(tmp_path / "cust"), "--realm", "example", "--origin", ORIGIN, "--key", str(kf),
            "--links", str(links), "--trustees", str(tmp_path / "set.json"), "--statement", str(tmp_path / "stmt.json"),
            "--unwitnessed"]


def test_the_signer_signs_through_the_custodian_and_its_positions_are_the_logs(binary, tmp_path):
    from keyclerk.desk import Desk
    from keyclerk.signer import Signer
    from keyclerk.store.log_desk import LogStore
    key = Ed25519PrivateKey.generate()
    links, size, root, head = migrated(tmp_path, key)
    ceremony(tmp_path, size, root, head)
    kf = keyfile(tmp_path / "records.key", key)
    out = run(binary, *recover_args(tmp_path, links, kf), "--sig", f"eva={tmp_path / 'eva.sig'}",
              "--sig", f"owner={tmp_path / 'owner.sig'}")
    assert out.returncode == 0, out.stderr
    c = Custodian(binary, tmp_path / "cust", kf)
    ck = c.start()
    signer = Signer(ck, tmp_path / "signer")
    try:
        store = LogStore(tmp_path / "desk", signer)
        a = {p["person"]: p["anchors"][0] for p in store.load()["persons"]}
        r = Desk(store).propose({"anchor": a["owner"], "roles": []}, {"action": "add_member", "group": "office-staff",
                                                                      "anchor": a["finn"], "days": 30, "reason": "joins"})
        assert r["outcome"] in ("applied", "pending"), r
        st = ck.state()
        assert st["size"] == signer.replica.size() > size and st["head"] == signer.replica.head().hex()
        assert st["root"] == signer.replica.root().hex()
        store.close()
    finally:
        signer.close()
        c.stop()


def test_one_body_per_position_and_only_the_next_one(custodian):
    c, ck, key = custodian
    first = message(link_body(0, L.ZERO))
    sig = ck.sign(first)
    assert ck.sign(first) == sig                                          # the same body again: the same signature
    with pytest.raises(CustodianRefused, match="one body per position"):
        ck.sign(message(link_body(0, L.ZERO, at="2026-11-07T12:00:01Z")))
    with pytest.raises(CustodianRefused, match="link 5 where link 1 comes next"):
        ck.sign(message(link_body(5, L.ZERO)))
    with pytest.raises(CustodianRefused, match="last link's hash"):
        ck.sign(message(link_body(1, "f" * 64)))
    with pytest.raises(CustodianRefused, match="realm"):
        ck.sign(message(link_body(1, ck.state()["head"], realm="another")))
    with pytest.raises(CustodianRefused, match="not canonical"):
        ck.sign(L._message(L.LINK_FORMAT, json.dumps(link_body(1, ck.state()["head"])).encode()))


def test_a_statement_only_over_what_the_custodian_computed(custodian):
    c, ck, key = custodian
    ck.sign(message(link_body(0, L.ZERO)))
    st = ck.state()
    good = {"format": L.CHECKPOINT_FORMAT, "realm": "example", "size": 1, "root": st["root"], "head": st["head"],
            "fence": 1, "at": "2026-11-07T12:00:00Z"}
    ck.sign(L._message(L.CHECKPOINT_FORMAT, E.canonical(good)))
    with pytest.raises(CustodianRefused, match="root or head"):
        ck.sign(L._message(L.CHECKPOINT_FORMAT, E.canonical({**good, "root": "a" * 64})))
    text = N.checkpoint_text(ORIGIN, 1, bytes.fromhex(st["root"]))
    ck.sign(text.encode())
    with pytest.raises(CustodianRefused, match="origin"):
        ck.sign(N.checkpoint_text("keyclerk.example/other", 1, bytes.fromhex(st["root"])).encode())
    with pytest.raises(CustodianRefused, match="leading zero"):
        ck.sign(text.replace("\n1\n", "\n01\n").encode())
    with pytest.raises(CustodianRefused, match="not a statement"):
        ck.sign(b"kc-something-else-v1\n{}")
    with pytest.raises(CustodianRefused, match="refused"):
        ck.sign(b"records: {}\n")                                          # a YAML revision: nothing of the log
    assert len(ck.sign(b"0" * 64)) == 64                                  # a log line's hash


def test_over_tcp_every_request_carries_the_token(custodian):
    c, ck, key = custodian
    with pytest.raises(CustodianRefused, match="wrong token"):
        CustodianKey(c.addr, "x" * 32).state()
    with pytest.raises(ValueError, match="token"):
        CustodianKey(c.addr)
    no_token = run(c.binary, "serve", "--state", str(c.state), "--realm", "example", "--key", str(c.key), "--listen",
                   f"tcp:127.0.0.1:{free_port()}", "--unwitnessed")
    assert no_token.returncode == 1


def test_a_missing_state_is_never_a_first_run_and_the_witness_is_required(binary, tmp_path):
    kf = keyfile(tmp_path / "k", Ed25519PrivateKey.generate())
    tok = tmp_path / "tok"
    tok.write_text("t" * 32)
    serve = ["serve", "--realm", "example", "--key", str(kf), "--listen", f"tcp:127.0.0.1:{free_port()}",
             "--token-file", str(tok)]
    out = run(binary, *serve, "--state", str(tmp_path / "none"), "--unwitnessed")
    assert out.returncode == 1 and "never a first run" in out.stderr
    init(binary, tmp_path / "s", kf)
    again = run(binary, "init", "--state", str(tmp_path / "s"), "--realm", "example", "--origin", ORIGIN, "--key", str(kf))
    assert again.returncode == 1 and "init starts a new log only" in again.stderr
    blind = run(binary, *serve, "--state", str(tmp_path / "s"))
    assert blind.returncode == 1 and "reads the witness" in blind.stderr
    other = run(binary, *[a if a != "example" else "production" for a in serve], "--state", str(tmp_path / "s"),
                "--unwitnessed")
    assert other.returncode == 1 and "never serves another realm" in other.stderr


def test_a_rotation_switches_at_the_next_link_and_destroys_the_old_key(custodian, binary, tmp_path):
    c, ck, key = custodian
    ck.sign(message(link_body(0, L.ZERO)))
    c.stop()
    nk = keyfile(tmp_path / "next.key", Ed25519PrivateKey.generate())
    base = ["rotate", "--state", str(c.state), "--realm", "example", "--key", str(c.key), "--next", str(nk),
            "--origin", "keyclerk.example/log-2"]
    bad = run(binary, *base, "--from-seq", "0")
    assert bad.returncode == 1 and "a planned rotation switches at the next link" in bad.stderr
    assert run(binary, *base, "--from-seq", "1").returncode == 0
    assert not c.key.exists()                                              # overwritten and removed (#41 F7)
    old = keyfile(tmp_path / "old-copy.key", key)
    back = run(binary, "serve", "--state", str(c.state), "--realm", "example", "--key", str(old), "--listen",
               f"tcp:127.0.0.1:{free_port()}", "--token-file", str(c.tokfile), "--unwitnessed")
    assert back.returncode == 1                                            # the state is sealed under the new key now
    c.key = nk
    assert c.start().state()["origin"] == "keyclerk.example/log-2"


def test_a_state_moves_once_and_a_watermark_is_sealed(custodian, binary, tmp_path):
    c, ck, key = custodian
    ck.sign(message(link_body(0, L.ZERO)))
    c.stop()
    out = tmp_path / "watermark.json"
    assert run(binary, "export", "--state", str(c.state), "--key", str(c.key), "--out", str(out)).returncode == 0
    gone = run(*c.args("--unwitnessed")[:1], *c.args("--unwitnessed")[1:])
    assert gone.returncode == 1 and "retired" in gone.stderr               # the exporter never serves again
    again = run(binary, "import", "--state", str(c.state), "--key", str(c.key), "--from", str(out))
    assert again.returncode == 1 and "retired" in again.stderr
    forged = json.loads(out.read_text())
    forged["size"] = 5
    (tmp_path / "forged.json").write_text(json.dumps(forged))
    bad = run(binary, "import", "--state", str(tmp_path / "new"), "--key", str(c.key), "--from", str(tmp_path / "forged.json"))
    assert bad.returncode == 1 and "seal" in bad.stderr
    assert run(binary, "import", "--state", str(tmp_path / "new"), "--key", str(c.key), "--from", str(out)).returncode == 0
    moved = Custodian(binary, tmp_path / "new", c.key)
    try:
        assert moved.start().state()["size"] == 1
    finally:
        moved.stop()


class Witness:
    """A commit witness standing in: it serves one cosigned checkpoint note."""

    def __init__(self):
        self.key, self.name = Ed25519PrivateKey.generate(), "witness.example/commit"
        self.vkey = N.vkey(self.name, N.COSIGNATURE, N.raw_public(self.key))
        self.served = {}
        w = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):   # noqa: N802
                body = w.served.get("note", "").encode()
                self.send_response(200 if body else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def note(self, size, root, origin=ORIGIN):
        text = N.checkpoint_text(origin, size, root)
        return text + "\n" + N.cosign(text, self.name, self.key, 1_800_000_000)


def test_a_state_behind_the_witness_signs_nothing_until_it_follows(custodian, binary):
    """Behind the witness (a standby restarted, a state restored from an older copy) the custodian serves with its floor
    raised and signs nothing; a standby follows on its own (the failover model, 2026-11-07), so a restart needs no
    ceremony. Another tree at its size, a witness gone back, or none for a log with links: it does not serve."""
    c, ck, key = custodian
    ck.sign(message(link_body(0, L.ZERO)))
    st = ck.state()
    c.stop()
    w = Witness()
    with_witness = ("--witness", w.url, "--witness-vkey", w.vkey)
    try:
        assert run(*c.args(*with_witness)).returncode == 1                 # 404 for a log with links: refused
        w.served["note"] = w.note(1, b"\x07" * 32)
        out = run(*c.args(*with_witness))
        assert out.returncode == 1 and "another tree" in out.stderr
        w.served["note"] = w.note(1, bytes.fromhex(st["root"]))
        assert c.start(*with_witness).state()["witness"] == 1               # the floor is kept
        c.stop()
        w.served["note"] = w.note(5, merkle.EMPTY)
        behind = c.start(*with_witness)
        assert behind.state()["witness"] == 5 and behind.state()["size"] == 1
        with pytest.raises(CustodianRefused, match="follows the committed log"):
            behind.sign(message(link_body(1, st["head"])))
        c.stop()
        w.served["note"] = w.note(1, bytes.fromhex(st["root"]))
        out = run(*c.args(*with_witness))                                  # the raised floor was persisted
        assert out.returncode == 1 and "rolled back" in out.stderr
    finally:
        w.srv.shutdown()


def test_two_nodes_custodians_follow_the_committed_log_on_the_witness_word(binary, tmp_path):
    """Decision 0033 Q4 and point 2 in HA: each node's custodian holds the same key; a standby's custodian takes the
    links the active node committed in one staged follow, landing exactly on the witness's tree; a deposed one whose
    own tail the committed log replaced rebuilds from link 0 once the witness has passed that tail, and never before."""
    key = Ed25519PrivateKey.generate()
    w = Witness()
    nodes = {}
    for n in ("a", "b"):
        kf = keyfile(tmp_path / f"{n}.key", key)
        init(binary, tmp_path / n, kf, origin="keyclerk.example/l")
        nodes[n] = Custodian(binary, tmp_path / n, kf)
    a = nodes["a"].start("--unwitnessed", "--witness-vkey", w.vkey)
    b = nodes["b"].start("--unwitnessed", "--witness-vkey", w.vkey)

    def note(ck):
        st = ck.state()
        return w.note(st["size"], bytes.fromhex(st["root"]), origin="keyclerk.example/l")
    try:
        links = chain(a, [], 3)
        at3 = note(a)
        assert b.follow("extend", links, at3) == 3 and b.state()["root"] == a.state()["root"]
        chain(b, list(links), 1, at="2026-11-07T13:00:00Z")                  # b's own position 3, never committed
        with pytest.raises(CustodianRefused, match="never signs a position twice"):
            b.follow("rebuild", links, at3)                                  # the witness has not passed b's tail
        committed = chain(a, list(links), 3)                                 # a commits other bodies from 3 on
        with pytest.raises(CustodianRefused):
            b.follow("extend", committed[3:], note(a))                       # b's own tail does not chain
        assert b.follow("rebuild", committed, note(a)) == 6 and b.state()["root"] == a.state()["root"]
        with pytest.raises(CustodianRefused, match="never below the floor"):
            b.follow("extend", [], w.note(3, bytes(32), origin="keyclerk.example/l"))
    finally:
        for c in nodes.values():
            c.stop()
        w.srv.shutdown()


def test_a_log_reaches_a_custodian_only_through_the_two_person_ceremony(binary, tmp_path):
    """Point 4, Q6, and the 2026-11-07 review's A7: a log moves to a custodian, or a lost state comes back, only on a
    kc-custodian-recovery-v1 statement an officer and a root trust owner of the pinned set signed; the statement's bytes
    are canonical, so every language reads the same; the old state is kept beside the new one."""
    key = Ed25519PrivateKey.generate()
    links, size, root, head = migrated(tmp_path, key)
    stmt = ceremony(tmp_path, size, root, head)
    kf = keyfile(tmp_path / "records.key", key)
    base = recover_args(tmp_path, links, kf)
    two_officers = run(binary, *base, "--sig", f"eva={tmp_path / 'eva.sig'}", "--sig", f"ingrid={tmp_path / 'ingrid.sig'}")
    assert two_officers.returncode == 1 and "one officer and one root trust owner" in two_officers.stderr
    sloppy = tmp_path / "sloppy.json"
    sloppy.write_text(json.dumps(json.loads(stmt), indent=1))                 # the same fields, not canonical
    out = run(binary, *[str(sloppy) if a == str(tmp_path / "stmt.json") else a for a in base],
              "--sig", f"eva={tmp_path / 'eva.sig'}", "--sig", f"owner={tmp_path / 'owner.sig'}")
    assert out.returncode == 1 and "canonical" in out.stderr
    out = run(binary, *base, "--sig", f"eva={tmp_path / 'eva.sig'}", "--sig", f"owner={tmp_path / 'owner.sig'}")
    assert out.returncode == 0, out.stderr
    c = Custodian(binary, tmp_path / "cust", kf)
    try:
        assert c.start().state()["size"] == size
    finally:
        c.stop()
    (tmp_path / "cust" / "custodian-state.json").write_text("{broken")
    again = run(binary, *base, "--sig", f"eva={tmp_path / 'eva.sig'}", "--sig", f"owner={tmp_path / 'owner.sig'}")
    assert again.returncode == 0, again.stderr                                # an unreadable state is recovered
    assert list((tmp_path / "cust").glob("custodian-state.json.lost-*"))


def test_a_recovery_is_recorded_in_the_log_once_by_the_signer(binary, tmp_path):
    """Decision 0033 Q6: the ceremony's marker. The custodian keeps the statement the trustees signed; the signer records
    it in the log as its own record, once, so every verifier sees where the trustees vouched for the log."""
    import hashlib

    from keyclerk.records import SIGNER_KINDS
    from keyclerk.signer import Signer
    from keyclerk.store import replay
    key = Ed25519PrivateKey.generate()
    links, size, root, head = migrated(tmp_path, key)
    stmt = ceremony(tmp_path, size, root, head)
    kf = keyfile(tmp_path / "records.key", key)
    out = run(binary, *recover_args(tmp_path, links, kf), "--sig", f"eva={tmp_path / 'eva.sig'}",
              "--sig", f"owner={tmp_path / 'owner.sig'}")
    assert out.returncode == 0, out.stderr
    c = Custodian(binary, tmp_path / "cust", kf)
    ck = c.start()
    signer = Signer(ck, tmp_path / "signer")
    try:
        mark = ck.state()["recovered"]
        assert mark["size"] == size and sorted(mark["trustees"]) == ["eva", "owner"]
        assert signer.record_custodian_recovery() is True
        got = replay.records(signer.replica)["custodian_recoveries"]
        assert [x["statement"] for x in got] == [mark["statement"]] and got[0]["size"] == size
        assert mark["statement"] == hashlib.sha256(stmt).hexdigest()
        assert signer.record_custodian_recovery() is False                   # once
        assert "custodian_recoveries" in SIGNER_KINDS                        # never from a desk
    finally:
        signer.close()
        c.stop()
