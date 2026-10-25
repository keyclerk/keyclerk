# SPDX-License-Identifier: EUPL-1.2
"""Decision 0016 through the desk: an assured edge enrolls with an officer-signed TPM commitment, proves its AK by
credential activation, and is assured on a pull only with a quote bound to that request at the PCR baseline. Quotes are
from a software TPM (tests/fixtures/tpm/make.sh), bound to edge plant-a at 2026-10-24T08:00Z."""
import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from keyclerk import attest as A
from keyclerk import config
from keyclerk import edge as E
from keyclerk.desk import Refusal

from test_edges import EDGE_KEY, EVA, FINN, INGRID, OFFICER_KEY, OWNER, W, cosigned, desk, statement  # noqa: F401 - fixture

T = Path(__file__).resolve().parent / "fixtures" / "tpm"
B64 = lambda b: base64.b64encode(b).decode()   # noqa: E731
EK_DER = serialization.load_pem_public_key((T / "ek.pub").read_bytes()).public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
TPM = {"ek_public": B64(EK_DER), "ek_sha256": __import__("hashlib").sha256(EK_DER).hexdigest(),
       "ak_public": B64((T / "ak.tpmt").read_bytes()), "ek_cert": B64((T / "ek-cert.der").read_bytes()),
       "pcr_baseline": {"7": "00" * 32}}
REQ1, REQ2 = ("1792828800", "reqnonce000000000001"), ("1792828800", "reqnonce000000000002")


def header(n):
    return ".".join(B64((T / f"bound{n}.{x}").read_bytes()) for x in ("msg", "sig", "pcrs"))


def enrol(desk, tpm=TPM, signed=None):
    st = statement("plant-a", EVA, OFFICER_KEY, tpm=E.tpm_commitment(signed or tpm))
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(EDGE_KEY),
                                "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured", "tpm": tpm,
                                "statement": cosigned(st, OFFICER_KEY, EDGE_KEY),
                                "custodians": [FINN, "idp:77dd-gina"],
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    if r["outcome"] == "pending":
        r = desk.approve(W(INGRID), r["change_id"])
    return r


@pytest.fixture
def roots(monkeypatch):
    real = config.current
    monkeypatch.setattr(config, "current", lambda: {**real(), "edges": {
        "ek_roots": [(T / "swtpm-localca-rootca-cert.pem").read_text()], "ek_intermediates": [(T / "issuercert.pem").read_text()]}})


def test_the_officer_signs_the_tpm_commitment_and_a_mismatch_is_refused(desk):
    other = {**TPM, "pcr_baseline": {"7": "11" * 32}}
    r = enrol(desk, tpm=TPM, signed=other)                     # the officer signed another baseline
    assert r["outcome"] == "refused" and any("not this record's (nodes differ)" in x for x in r["reasons"])
    bad = enrol(desk, tpm={**TPM, "ek_sha256": "0" * 64})
    assert bad["outcome"] == "refused" and any("ek_sha256 is not the fingerprint" in x for x in bad["reasons"])
    assert enrol(desk)["outcome"] == "applied"


def test_activation_proves_the_ak_is_in_the_pinned_tpm(desk, roots, monkeypatch):
    enrol(desk)
    ch = desk.edge_attest_challenge("plant-a")
    assert base64.b64decode(ch["credential"])[:4] == bytes.fromhex("badcc0de")
    with pytest.raises(Refusal, match="wrong answer"):
        desk.edge_attest_activate("plant-a", {"secret": B64(b"x" * 32)})
    assert any(i["kind"] == "attestation_failed" for i in desk.edge_store.incidents("plant-a"))
    with pytest.raises(Refusal, match="no challenge waits"):                       # a wrong answer burns the challenge
        desk.edge_attest_activate("plant-a", {"secret": B64(b"x" * 32)})
    monkeypatch.setattr("keyclerk.desk.secrets.token_bytes", lambda n: b"s" * n)  # what the TPM would recover
    desk.edge_attest_challenge("plant-a")
    assert desk.edge_attest_activate("plant-a", {"secret": B64(b"s" * 32)})["activated"]


def test_without_a_manufacturer_root_that_chains_the_ek_certificate_there_is_no_challenge(desk):
    enrol(desk)
    with pytest.raises(Refusal, match="endorsement key does not hold"):
        desk.edge_attest_challenge("plant-a")


def test_a_pull_is_assured_only_with_an_activated_ak_and_a_bound_quote_at_the_baseline(desk, roots, monkeypatch):
    enrol(desk)
    e = next(x for x in desk.store.load()["edges"] if x["edge_id"] == "plant-a")
    assert desk._attested(e, "plant-a", header(1), REQ1) == ("basic", ["the attestation key is not activated (GET /edge/attest/challenge)"])
    monkeypatch.setattr("keyclerk.desk.secrets.token_bytes", lambda n: b"s" * n)
    desk.edge_attest_challenge("plant-a")
    desk.edge_attest_activate("plant-a", {"secret": B64(b"s" * 32)})
    assert desk._attested(e, "plant-a", None, REQ1)[0] == "basic"                 # no quote, no assurance
    assert desk._attested(e, "plant-a", header(1), REQ1) == ("assured", [])
    stale = desk._attested(e, "plant-a", header(1), REQ2)                          # the quote of another request
    assert stale[0] == "basic" and "another nonce" in stale[1][0]
    moved = desk._attested(e, "plant-a", header(2), REQ2)                          # PCR 7 changed after enrolment
    assert moved == ("basic", ["PCR 7 is not the baseline the officer signed"])
    assert desk.edge_store.state("plant-a")["attested"] == "basic"
    kinds = [i["detail"] for i in desk.edge_store.incidents("plant-a") if i["kind"] == "attestation_failed"]
    assert any("PCR 7" in k for k in kinds)


def test_an_edge_without_a_tpm_is_basic(desk):
    from test_edges import enrol as plain
    r = plain(desk)
    desk.approve(W(INGRID), r["change_id"])
    e = next(x for x in desk.store.load()["edges"] if x["edge_id"] == "plant-a")
    assert desk._attested(e, "plant-a", header(1), REQ1) == ("basic", ["enrolled without a TPM"])
    with pytest.raises(Refusal, match="without a TPM"):
        desk.edge_attest_challenge("plant-a")
