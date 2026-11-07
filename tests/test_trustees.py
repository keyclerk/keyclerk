# SPDX-License-Identifier: EUPL-1.2
"""Trustee keys (#41): a set pinned out of band, signatures in three forms, a threshold of one officer and one root
trust owner, and a next set only by the current threshold plus possession of every new key."""
import base64
import copy
import hashlib
import shutil
import struct
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from keyclerk import trustees as T

REALM = "example"
NS = f"keyclerk-trustee@{REALM}"
STATEMENT = b'{"format":"kc-test-v1","n":1}'


def s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ssh_blob(k, sk=False) -> bytes:
    if sk:
        return s(b"sk-ssh-ed25519" + b"@" + b"openssh.com") + s(raw(k)) + s(b"ssh:")
    return s(b"ssh-ed25519") + s(raw(k))


def sshsig(k, message: bytes, sk=False, flags=T.UP, namespace=NS) -> str:
    """An SSHSIG as ssh-keygen -Y sign makes it; for sk, as a FIDO2 authenticator signs its envelope."""
    h = hashlib.sha512(message).digest()
    signed = b"SSHSIG" + s(namespace.encode()) + s(b"") + s(b"sha512") + s(h)
    if sk:
        counter = struct.pack(">I", 7)
        inner = k.sign(hashlib.sha256(b"ssh:").digest() + bytes([flags]) + counter + hashlib.sha256(signed).digest())
        sigblob = s(b"sk-ssh-ed25519" + b"@" + b"openssh.com") + s(inner) + bytes([flags]) + counter
    else:
        sigblob = s(b"ssh-ed25519") + s(k.sign(signed))
    blob = b"SSHSIG" + struct.pack(">I", 1) + s(ssh_blob(k, sk)) + s(namespace.encode()) + s(b"") + s(b"sha512") + s(sigblob)
    return "-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(blob).decode() + "\n-----END SSH SIGNATURE-----\n"


KEYS = {n: Ed25519PrivateKey.generate() for n in ("eva", "ingrid", "owner", "olga", "newbie")}


def trustee(tid, anchor, role, k, kind):
    if kind == "ed25519":
        key = {"type": "ed25519", "public_key": raw(k).hex()}
    else:
        key = {"type": kind, "public_key": base64.b64encode(ssh_blob(k, kind == "sk-ssh-ed25519")).decode()}
    return {"trustee_id": tid, "anchor": anchor, "role": role, "key": key}


def sign(tid, kind, label=T.FORMAT, body=STATEMENT, **kw):
    k = KEYS[tid]
    msg = label.encode() + b"\n" + body
    return {"trustee_id": tid, "sig": k.sign(msg).hex() if kind == "ed25519" else sshsig(k, msg, kind == "sk-ssh-ed25519", **kw)}


@pytest.fixture
def ts():
    return {"format": T.FORMAT, "realm": REALM, "version": 1, "at": "2026-11-06T19:00:00Z", "trustees": [
        trustee("eva", "idp:55bb-eva", "officer", KEYS["eva"], "sk-ssh-ed25519"),
        trustee("ingrid", "idp:31ee-ingrid", "officer", KEYS["ingrid"], "ssh-ed25519"),
        trustee("owner", "idp:2b9e-owner", "root", KEYS["owner"], "ed25519"),
        trustee("olga", "idp:88ee-olga", "root", KEYS["olga"], "sk-ssh-ed25519")]}


def test_a_well_formed_set_passes(ts):
    assert T.check(ts) == []


def test_a_set_needs_two_of_each_role_and_nobody_in_both(ts):
    small = {**ts, "trustees": ts["trustees"][:3]}
    assert any("four to" in e for e in T.check(small))
    both = copy.deepcopy(ts)
    both["trustees"][2]["anchor"] = "idp:55bb-eva"
    assert any("never both officer and root" in e for e in T.check(both))
    one = copy.deepcopy(ts)
    one["trustees"][1]["role"] = "root"
    assert any("at least two officer" in e for e in T.check(one))


def test_each_signature_form_verifies(ts):
    by = {t["trustee_id"]: t for t in ts["trustees"]}
    for tid, kind in (("eva", "sk-ssh-ed25519"), ("ingrid", "ssh-ed25519"), ("owner", "ed25519")):
        T.verify(by[tid], REALM, T.FORMAT, STATEMENT, sign(tid, kind)["sig"])


def test_a_fido2_signature_without_user_presence_is_refused(ts):
    with pytest.raises(T.TrusteeRefused, match="without user presence"):
        T.verify(ts["trustees"][0], REALM, T.FORMAT, STATEMENT, sign("eva", "sk-ssh-ed25519", flags=0)["sig"])


def test_another_namespace_label_or_statement_does_not_verify(ts):
    eva = ts["trustees"][0]
    with pytest.raises(T.TrusteeRefused, match="namespace"):
        T.verify(eva, REALM, T.FORMAT, STATEMENT, sign("eva", "sk-ssh-ed25519", namespace="git")["sig"])
    with pytest.raises(T.TrusteeRefused, match="does not verify"):
        T.verify(eva, REALM, "kc-other-v1", STATEMENT, sign("eva", "sk-ssh-ed25519")["sig"])
    with pytest.raises(T.TrusteeRefused, match="does not verify"):
        T.verify(eva, REALM, T.FORMAT, STATEMENT + b" ", sign("eva", "sk-ssh-ed25519")["sig"])


def test_a_signature_by_another_key_is_refused(ts):
    with pytest.raises(T.TrusteeRefused, match="another key"):
        T.verify(ts["trustees"][1], REALM, T.FORMAT, STATEMENT, sign("eva", "ssh-ed25519")["sig"])


def test_the_threshold_is_one_officer_and_one_root_owner(ts):
    assert T.threshold(ts, T.FORMAT, STATEMENT, [sign("eva", "sk-ssh-ed25519"), sign("owner", "ed25519")]) == ["eva", "owner"]
    with pytest.raises(T.TrusteeRefused, match="one officer and one root"):
        T.threshold(ts, T.FORMAT, STATEMENT, [sign("eva", "sk-ssh-ed25519"), sign("ingrid", "ssh-ed25519")])
    with pytest.raises(T.TrusteeRefused, match="no trustee of the pinned set"):
        T.threshold(ts, T.FORMAT, STATEMENT, [{"trustee_id": "mallory", "sig": "00"}, sign("owner", "ed25519")])


def test_the_next_set_needs_the_current_threshold_and_possession_of_new_keys(ts):
    nxt = copy.deepcopy(ts)
    nxt["version"] = 2
    nxt["trustees"][3] = trustee("newbie", "idp:99ff-nina", "root", KEYS["newbie"], "ssh-ed25519")
    body = T.canonical(nxt)
    sigs = [sign("ingrid", "ssh-ed25519", body=body), sign("owner", "ed25519", body=body)]
    with pytest.raises(T.TrusteeRefused, match="proves possession"):
        T.next_set(ts, nxt, sigs, [])
    accept = [sign("newbie", "ssh-ed25519", label=T.ACCEPT, body=body)]
    assert T.next_set(ts, nxt, sigs, accept)["version"] == 2
    with pytest.raises(T.TrusteeRefused, match="never skipped"):
        T.next_set(ts, {**nxt, "version": 3}, sigs, accept)
    with pytest.raises(T.TrusteeRefused, match="one officer and one root"):   # the new key alone cannot let itself in
        T.next_set(ts, nxt, [sign("ingrid", "ssh-ed25519", body=body)], accept)


def test_garbage_signatures_are_refusals(ts):
    for bad in ("", "x" * 20000, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----",
                base64.b64encode(b"SSHSIG\x00\x00\x00\x01\xff\xff\xff\xff").decode(), "zz"):
        with pytest.raises(T.TrusteeRefused):
            T.verify(ts["trustees"][0], REALM, T.FORMAT, STATEMENT, bad)
        with pytest.raises(T.TrusteeRefused):
            T.verify(ts["trustees"][2], REALM, T.FORMAT, STATEMENT, bad)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="OpenSSH's ssh-keygen is not installed")
def test_a_signature_made_by_openssh_itself_verifies(tmp_path):
    """Interop: the verifier reads what ssh-keygen -Y sign writes, for a key OpenSSH generated."""
    key = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    msg = tmp_path / "statement"
    msg.write_bytes(T.FORMAT.encode() + b"\n" + STATEMENT)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-n", NS, "-f", str(key), str(msg)], check=True,
                   capture_output=True)
    t = {"trustee_id": "card", "anchor": "idp:x", "role": "officer",
         "key": T.public_key_of((tmp_path / "id_ed25519.pub").read_text())}
    T.verify(t, REALM, T.FORMAT, STATEMENT, (tmp_path / "statement.sig").read_text())
    with pytest.raises(T.TrusteeRefused):
        T.verify(t, REALM, T.FORMAT, STATEMENT + b"!", (tmp_path / "statement.sig").read_text())


from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@settings(max_examples=400, deadline=None)
@given(st.binary(max_size=600))
def test_any_bytes_as_an_sshsig_are_a_refusal_or_a_pass(blob):
    t = trustee("eva", "idp:55bb-eva", "officer", KEYS["eva"], "sk-ssh-ed25519")
    for sig in (base64.b64encode(b"SSHSIG" + blob).decode(), blob.hex()):
        try:
            T.verify(t, REALM, T.FORMAT, STATEMENT, sig)
        except T.TrusteeRefused:
            pass


def pinned_set(realm: str) -> dict:
    """A raw-Ed25519 trustee set for tests that pin trustees (two officers, two root trust owners)."""
    people = [("eva", "idp:55bb-eva", "officer"), ("ingrid", "idp:31ee-ingrid", "officer"),
              ("owner", "idp:2b9e-owner", "root"), ("olga", "idp:88ee-olga", "root")]
    return {"format": T.FORMAT, "realm": realm, "version": 1, "at": "2026-11-06T19:00:00Z",
            "trustees": [trustee(t, a, r, KEYS[t], "ed25519") for t, a, r in people]}


def trustee_sigs(label: str, statement: bytes, who=("eva", "owner")) -> list[dict]:
    """Raw Ed25519 signatures of the pinned_set's trustees over label + "\n" + statement."""
    return [{"trustee_id": t, "sig": KEYS[t].sign(label.encode() + b"\n" + statement).hex()} for t in who]


def test_n10_a_reserved_field_in_an_ssh_signature_is_refused(ts):
    """0.29 review N10: OpenSSH writes the reserved field empty; one carrying bytes is refused even when it verifies."""
    k, msg = KEYS["ingrid"], T.FORMAT.encode() + b"\n" + STATEMENT
    h = hashlib.sha512(msg).digest()
    signed = b"SSHSIG" + s(NS.encode()) + s(b"x") + s(b"sha512") + s(h)
    blob = b"SSHSIG" + struct.pack(">I", 1) + s(ssh_blob(k)) + s(NS.encode()) + s(b"x") + s(b"sha512") + \
        s(s(b"ssh-ed25519") + s(k.sign(signed)))
    sig = "-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(blob).decode() + "\n-----END SSH SIGNATURE-----\n"
    with pytest.raises(T.TrusteeRefused, match="reserved"):
        T.verify(ts["trustees"][1], REALM, T.FORMAT, STATEMENT, sig)


def test_n10_a_malformed_set_gives_reasons_never_a_type_error(ts):
    for bad in ({"anchor": ["x"]}, {"role": ["officer"]}, {"key": {"type": "ed25519", "public_key": ["x"]}},
                {"trustee_id": ["x"]}):
        broken = {**ts, "trustees": [{**ts["trustees"][0], **bad}] + ts["trustees"][1:]}
        assert T.check(broken)


def test_n10_one_trustee_set_per_process(ts):
    T.use(ts)
    try:
        T.use(ts)                                           # the same set again: fine
        with pytest.raises(T.TrusteeRefused, match="another trustee set"):
            T.use({**ts, "version": 2})
    finally:
        T.use(None)


def test_n10_the_next_set_cli_writes_only_a_verified_set(ts, tmp_path):
    import json
    nxt = {**ts, "version": 2, "at": "2026-11-07T10:00:00Z"}
    body = T.canonical(nxt)
    (tmp_path / "cur.json").write_text(json.dumps(ts))
    (tmp_path / "next.json").write_text(json.dumps(nxt))
    (tmp_path / "sigs.json").write_text(json.dumps([sign("eva", "sk-ssh-ed25519", body=body),
                                                    sign("owner", "ed25519", body=body)]))
    (tmp_path / "acc.json").write_text("[]")
    out = tmp_path / "pinned.json"
    args = [str(tmp_path / x) for x in ("cur.json", "next.json", "sigs.json", "acc.json")] + [str(out)]
    assert T.main(["next"] + args) == 0 and json.loads(out.read_text())["version"] == 2
    (tmp_path / "sigs.json").write_text(json.dumps([sign("eva", "sk-ssh-ed25519", body=body)]))
    out.unlink()
    assert T.main(["next"] + args) == 1 and not out.exists()
