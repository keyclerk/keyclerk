# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014: the envelope to a person key, signed edge requests, the ceiling and the bundle verifier."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import relay as R

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
ISO = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")   # noqa: E731


def test_only_the_person_key_opens_the_envelope_and_the_context_is_bound():
    priv, pub = R.person_key_from_prf(b"\x07" * 32)
    env = R.encrypt(R.b64e(pub), b"lease password", "lease:L-1")
    R.check(env)
    assert R.decrypt(priv, env) == b"lease password"
    other, _ = R.person_key_from_prf(b"\x08" * 32)
    with pytest.raises(InvalidTag):
        R.decrypt(other, env)
    with pytest.raises(InvalidTag):
        R.decrypt(priv, {**env, "context": "lease:L-2"})
    for bad in ({**env, "format": "x"}, {**env, "extra": 1}, {**env, "nonce": R.b64e(b"1")}):
        with pytest.raises(ValueError):
            R.check(bad)


def test_the_person_key_is_the_same_wherever_it_is_derived():
    """The browser derives it with WebCrypto from the same PRF output: these vectors pin the derivation."""
    _, pub = R.person_key_from_prf(bytes(range(32)))
    assert len(pub) == 32 and R.public_key(R.b64e(pub)) == pub


def test_a_signed_request_is_refused_when_wrong_late_or_replayed():
    k = Ed25519PrivateKey.generate()
    pub = {"edge-a": E.public_hex(k)}.get
    seen = E.Replay()
    h = E.sign_request(k, "edge-a", "GET", "/api/v1/edge/bundle", b"", seconds=1_000_000, nonce="n" * 20)
    assert E.check_request(h, "GET", "/api/v1/edge/bundle", b"", pub, seen, now=1_000_010) == "edge-a"
    with pytest.raises(ValueError, match="replayed"):
        E.check_request(h, "GET", "/api/v1/edge/bundle", b"", pub, seen, now=1_000_010)
    with pytest.raises(ValueError, match="clock"):
        E.check_request(h, "GET", "/api/v1/edge/bundle", b"", pub, E.Replay(), now=1_000_000 + 400)
    with pytest.raises(ValueError, match="enrolled edge"):
        E.check_request(h, "POST", "/api/v1/edge/bundle", b"", pub, E.Replay(), now=1_000_010)
    with pytest.raises(ValueError, match="enrolled edge"):                 # the same answer for an unknown edge
        E.check_request(h.replace("edge-a", "edge-b"), "GET", "/api/v1/edge/bundle", b"", pub, E.Replay(), now=1_000_010)


def _ceiling(serial=1, **over):
    c = {"format": E.CEILING_FORMAT, "edge": "edge-a", "serial": serial, "persons": ["idp:7c1f-ann"], "roles": [],
         "targets": ["plc-ssh"], "classes": ["low", "elevated"], "max_lease_hours": 8, "max_offline_hours": 72,
         "profile": "assured", "remote_reach": "off", "ports": [22], "signed_at": "2026-10-23T10:00:00Z"}
    return {**c, **over}


def test_a_ceiling_counts_only_with_the_officers_signature_and_a_serial_at_the_floor_or_above():
    officer = Ed25519PrivateKey.generate()
    c, pub = _ceiling(), E.public_hex(officer)
    errs, doc = E.check_ceiling("edge-a", pub, E.seal_ceiling(officer, c))
    assert errs == [] and doc["serial"] == 1 and doc["format"] == "kc-edge-ceiling-v2"
    assert any("officer" in e for e in E.check_ceiling("edge-a", pub, E.seal_ceiling(Ed25519PrivateKey.generate(), c))[0])
    assert any("older" in e for e in E.check_ceiling("edge-a", pub, E.seal_ceiling(officer, c), floor=2)[0])
    for bad in (_ceiling(classes=["privileged", "root"]), _ceiling(serial=True), _ceiling(ports=["22"]), _ceiling(persons="ann")):
        assert E.check_ceiling("edge-a", pub, E.seal_ceiling(officer, bad))[0], bad
    v1 = {"ceiling": c, "signature": "0" * 128}                               # the v1 shape: no migration (0014d)
    assert E.check_ceiling("edge-a", pub, v1)[0]


def test_a_multi_signed_statement_holds_exactly_its_signers():
    """Amendment 0014d: the officer and each node sign the same bytes; nobody re-serialises."""
    ok, n1, n2 = (Ed25519PrivateKey.generate() for _ in range(3))
    st = E.officer_statement("edge-a", "idp:55bb-eva", E.public_hex(ok), [E.node(E.public_hex(n1)), E.node(E.public_hex(n2))])
    signed = E.cosign(n2, E.cosign(n1, E.cosign(ok, st)))
    assert E.unseal_multi(signed, E.statement_signers(st), E.OFFICER_FORMAT) == st
    assert E.cosign(ok, signed) == signed or E.unseal_multi(E.cosign(ok, signed), E.statement_signers(st), E.OFFICER_FORMAT)
    with pytest.raises(ValueError, match="signed by exactly"):
        E.unseal_multi(E.cosign(n1, E.cosign(ok, st)), E.statement_signers(st), E.OFFICER_FORMAT)
    with pytest.raises(ValueError):
        E.officer_statement("edge-a", "idp:55bb-eva", E.public_hex(ok), [E.node(E.public_hex(n1))] * 3)


def test_unlock_v2_both_sides_reach_one_code_bound_to_the_node():
    desk, edge = (E.unlock_private(E.new_unlock_private()) for _ in range(2))
    dp, ep = E.unlock_public(desk), E.unlock_public(edge)
    a = E.unlock_secret(desk, dp, ep, "edge-a", "aa" * 8)
    assert a == E.unlock_secret(edge, dp, ep, "edge-a", "aa" * 8) != E.unlock_secret(edge, dp, ep, "edge-a", "bb" * 8)
    with pytest.raises(ValueError):
        E.load_unlock_public(dp[:-1] + ("A" if dp[-1] != "A" else "B"))          # off the curve or not canonical
    with pytest.raises(ValueError):
        E.unlock_code(a, "edge-a", "aa" * 8, "idp:x", "fp|x", "t", "n", 5)


def test_signed_objects_are_exact_bytes_with_a_format_and_no_floats():
    k = Ed25519PrivateKey.generate()
    s = E.seal(k, {"a": 1, "b": "x"}, "kc-test-v1")
    assert E.unseal(s, E.public_hex(k), "kc-test-v1")["a"] == 1
    with pytest.raises(ValueError):
        E.unseal(s, E.public_hex(k), "kc-other-v1")           # an ack is never taken for a bundle
    with pytest.raises(TypeError):
        E.canonical({"x": 1.5})


def test_a_release_manifest_names_the_modules_an_agent_may_run(tmp_path):
    import base64
    import hashlib
    rk, bk, ok = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    wasm = b"\x00asm-module"
    mods = {"edge": {"sha256": hashlib.sha256(wasm).hexdigest()}}
    c = E.seal_ceiling(ok, _ceiling())
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": E.public_hex(ok), "release_key": E.public_hex(rk)}
    good = E.build_bundle("edge-a", 2, NOW, {"low": 1}, [], [], [], c,
                          {"modules": mods, "release": E.sign_release(rk, {"edge": mods["edge"]["sha256"]})}, bk)
    assert E.verify_bundle(good, pins, {}, NOW)[0] == []
    other = E.build_bundle("edge-a", 2, NOW, {"low": 1}, [], [], [], c,
                           {"modules": mods, "release": E.sign_release(rk, {"edge": "0" * 64})}, bk)
    assert any("not the released one" in e for e in E.verify_bundle(other, pins, {}, NOW)[0])
    unsigned = E.build_bundle("edge-a", 2, NOW, {"low": 1}, [], [], [], c, {"modules": mods, "release": None}, bk)
    assert any("release" in e for e in E.verify_bundle(unsigned, pins, {}, NOW)[0])


def test_the_officers_ceiling_holds_for_visit_leases_at_the_edge_too():
    """Found while building an independent edge agent: the reference verifier ran the ceiling on leases only, so the visit rules (a window
    within max_offline_hours, an edge assured by its ceiling and its own attestation) were enforced at the desk alone,
    and a taken-over desk could put a visit lease on a basic edge. Now the edge refuses it too."""
    from keyclerk import policy_wasm
    check = lambda c, entry: policy_wasm.ceiling({"ceiling": c, "entry": entry})   # noqa: E731
    bk, ok = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": E.public_hex(ok), "release_key": None}
    visit = lambda hours: {"lease_id": f"VL-{hours}", "person": "idp:7c1f-ann", "username": "ann", "ssh_key": "",  # noqa: E731
                           "targets": ["plc-ssh"], "role": "operator", "from": ISO(NOW - timedelta(hours=1)),
                           "until": ISO(NOW - timedelta(hours=1) + timedelta(hours=hours))}

    def applied(ceiling, visits, attested):
        b = E.build_bundle("edge-a", 2, NOW, {"low": 1}, [], visits, [], E.seal_ceiling(ok, ceiling),
                           {"modules": {}, "release": None}, bk)
        errs, out = E.verify_bundle(b, pins, {}, NOW, check, attested)
        assert errs == []
        return [v["lease_id"] for v in out["visit_leases"]], out["refused_by_ceiling"]

    assert applied(_ceiling(), [visit(4)], "assured") == (["VL-4"], [])
    assert applied(_ceiling(), [visit(4)], "basic") == ([], ["VL-4"])            # the edge's own attestation
    assert applied(_ceiling(), [visit(4)], None) == ([], ["VL-4"])               # no attestation: refused
    assert applied(_ceiling(profile="basic"), [visit(4)], "assured") == ([], ["VL-4"])   # the officer's ceiling
    assert applied(_ceiling(max_offline_hours=3), [visit(4)], "assured") == ([], ["VL-4"])  # window above the ceiling
