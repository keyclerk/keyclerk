"""The change log's C2SP form (keyclerk.store.note) and consistency proofs (keyclerk.store.merkle) against notes and
proofs made by independent Go implementations (tests/conformance/c2sp-go.json, tools/interop/c2sp): every byte must be
the same, so a witness or verifier built on them reads KeyClerk's."""
import base64
import json
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk.store import merkle
from keyclerk.store import note as N

GO = json.loads((Path(__file__).parent / "conformance" / "c2sp-go.json").read_text(encoding="utf-8"))
LOG_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(GO["log_seed"]))
WITNESS_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(GO["witness_seed"]))
LOG_V, WIT_V = N.parse_vkey(GO["log_vkey"]), N.parse_vkey(GO["witness_vkey"])
LEAVES = [merkle.leaf(d.encode()) for d in GO["leaves"]]


def test_the_vkeys_are_the_ones_go_derives():
    assert N.vkey(GO["origin"], N.LOG, N.raw_public(LOG_KEY)) == GO["log_vkey"]
    assert N.vkey(WIT_V[0], N.COSIGNATURE, N.raw_public(WITNESS_KEY)) == GO["witness_vkey"]


@pytest.mark.parametrize("cp", GO["checkpoints"], ids=lambda c: f"size{c['size']}")
def test_checkpoints_and_signatures_are_byte_for_byte_gos(cp):
    root = merkle.mth(LEAVES[:cp["size"]])
    assert N.b64(root) == cp["root"]
    text = N.checkpoint_text(GO["origin"], cp["size"], root)
    assert N.parse_checkpoint(text) == (GO["origin"], cp["size"], root)
    lines = cp["note"][len(text) + 1:]
    assert cp["note"] == text + "\n" + lines
    assert N.sign(text, GO["origin"], LOG_KEY) + N.cosign(text, WIT_V[0], WITNESS_KEY, cp["cosignature_time"]) == lines
    t, sigs = N.split(cp["note"])
    assert t == text and N.verify(t, sigs, LOG_V) == 0 and N.verify(t, sigs, WIT_V) == cp["cosignature_time"]


@pytest.mark.parametrize("cp", GO["checkpoints"], ids=lambda c: f"size{c['size']}")
def test_consistency_proofs_are_gos(cp):
    n, new = cp["size"], merkle.mth(LEAVES[:cp["size"]])
    for p in cp["proofs"] or []:
        proof, old = [base64.b64decode(h) for h in p["proof"]], merkle.mth(LEAVES[:p["from"]])
        assert merkle.consistency(LEAVES[:n], p["from"]) == proof
        assert merkle.consistent(p["from"], n, old, new, proof)


def test_every_proof_verifies_and_no_tampered_one_does():
    rnd = random.Random(5)
    leaves = [merkle.leaf(rnd.randbytes(8)) for _ in range(40)]
    for n in range(1, 41):
        new = merkle.mth(leaves[:n])
        for m in range(0, n + 1):
            old = merkle.mth(leaves[:m]) if m else merkle.EMPTY
            proof = merkle.consistency(leaves[:n], m)
            assert merkle.consistent(m, n, old, new, proof), (m, n)
            if 0 < m < n:
                bad = list(proof)
                i = rnd.randrange(len(bad))
                bad[i] = bytes([bad[i][0] ^ 1]) + bad[i][1:]
                assert not merkle.consistent(m, n, old, new, bad)
                assert not merkle.consistent(m, n, merkle.leaf(b"another"), new, proof)
                assert not merkle.consistent(m, n, old, new, proof + [old])
    assert merkle.consistent(0, 5, b"", merkle.mth(leaves[:5]), [])
    assert not merkle.consistent(0, 5, b"", merkle.mth(leaves[:5]), [leaves[0]])     # size 0 takes no proof
    assert not merkle.consistent(3, 3, merkle.mth(leaves[:3]), merkle.mth(leaves[:4]), [])   # same size, other root


def test_a_note_from_a_known_key_with_a_bad_signature_is_refused_and_unknown_keys_are_ignored():
    cp = GO["checkpoints"][3]
    text, sigs = N.split(cp["note"])
    other = Ed25519PrivateKey.generate()
    assert N.verify(text, sigs, (GO["origin"], N.LOG, N.raw_public(other))) is None      # same name, another key
    flipped = [(n, raw[:-1] + bytes([raw[-1] ^ 1])) if n == WIT_V[0] else (n, raw) for n, raw in sigs]
    with pytest.raises(N.NoteRefused, match="does not verify"):
        N.verify(text, flipped, WIT_V)
    with pytest.raises(N.NoteRefused, match="does not verify"):
        N.verify(text.replace(f"\n{cp['size']}\n", f"\n{cp['size'] + 1}\n"), sigs, LOG_V)


@pytest.mark.parametrize("bad, why", [
    ("o\n1\nAA==\n\n— o AAAAAAA=\n", "the root is 32 bytes"),
    ("o\n01\n" + "A" * 43 + "=\n", "no leading zero"),
    ("o\n1\n" + "A" * 43 + "=\next\n", "no extension lines"),
    ("o o\n1\n" + "A" * 43 + "=\n", "no space"),
])
def test_checkpoint_texts_are_strict(bad, why):
    with pytest.raises(N.NoteRefused, match=why):
        N.parse_checkpoint(N.split(bad)[0] if "\n\n" in bad else bad)


@pytest.mark.parametrize("bad, why", [
    ("t\n\n— k AAAAAAA\n", "base64"),
    ("t\n\n— k AAAAAAB=\n", "canonical"),
    ("t\n\n- k AAAAAAA=\n", "em dash"),
    ("t\x07\n\n— k AAAAAAA=\n", "control"),
    ("t\n\n", "em dash"),
    ("t\n", "an empty line"),
])
def test_notes_are_strict(bad, why):
    with pytest.raises(N.NoteRefused, match=why):
        N.split(bad)


def test_a_vkey_whose_id_is_not_its_key_is_refused():
    name, kid, rest = GO["witness_vkey"].split("+")
    with pytest.raises(N.NoteRefused, match="key id"):
        N.parse_vkey(f"{name}+{'0' * 8 if kid != '0' * 8 else '1' * 8}+{rest}")
    with pytest.raises(N.NoteRefused, match="key id"):
        N.parse_vkey(f"another.example/w+{kid}+{rest}")
