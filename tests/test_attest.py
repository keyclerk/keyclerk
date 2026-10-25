# SPDX-License-Identifier: EUPL-1.2
"""Decision 0016: TPM attestation, checked against vectors a software TPM made (tests/fixtures/tpm/make.sh: swtpm and
tpm2-tools, independent of this code). The software MakeCredential is checked against a TPM by
tests/fixtures/tpm/roundtrip.sh (a real activation for the AK's name, a refusal for any other name)."""
import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from keyclerk import attest as A

F = Path(__file__).resolve().parent / "fixtures" / "tpm"
AK = A.parse_public((F / "ak.tpmt").read_bytes())
EK = serialization.load_pem_public_key((F / "ek.pub").read_bytes())
ROOT, ISSUER = (F / "swtpm-localca-rootca-cert.pem").read_bytes(), (F / "issuercert.pem").read_bytes()
CERT = (F / "ek-cert.der").read_bytes()


def quote(n=""):
    return ((F / f"quote{n}.msg").read_bytes(), (F / f"quote{n}.sig").read_bytes(),
            A.pcr_values_file((F / f"quote{n}.pcrs").read_bytes(), [0, 7]), (F / f"nonce{n}.bin").read_bytes())


def test_the_ak_name_is_computed_as_the_tpm_computes_it_and_the_ak_is_a_restricted_signing_key():
    assert AK.name == (F / "ak.name").read_bytes()
    A.check_ak(AK)
    weak = A.Public(AK.raw, AK.type, AK.name_alg, AK.attributes & ~0x00010000, AK.key)     # not restricted
    with pytest.raises(A.AttestError, match="restricted signing key"):
        A.check_ak(weak)


def test_a_quote_verifies_and_reports_the_pcrs_and_a_changed_secure_boot_state_shows():
    facts = A.verify_quote(AK, *quote())
    assert facts["pcrs"]["7"] == "00" * 32 and facts["clock_safe"]
    changed = A.verify_quote(AK, *quote("2"))
    assert changed["pcrs"]["7"] != facts["pcrs"]["7"]                    # policy sees PCR 7 move


def test_a_quote_is_refused_for_another_nonce_other_pcr_values_a_tampered_message_or_another_key():
    msg, sig, pcrs, nonce = quote()
    with pytest.raises(A.AttestError, match="another nonce"):
        A.verify_quote(AK, msg, sig, pcrs, b"x" * len(nonce))
    with pytest.raises(A.AttestError, match="do not match the quoted digest"):
        A.verify_quote(AK, msg, sig, {**pcrs, 7: bytes(31) + b"\x01"}, nonce)
    with pytest.raises(A.AttestError, match="not the PCRs quoted"):
        A.verify_quote(AK, msg, sig, {7: pcrs[7]}, nonce)
    m2, s2, p2, n2 = quote("2")
    with pytest.raises(A.AttestError, match="signature"):                # one quote's message with another's signature
        A.verify_quote(AK, m2, sig, p2, n2)
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(A.AttestError, match="signature"):
        A.verify_quote(A.Public(AK.raw, AK.type, AK.name_alg, AK.attributes, other), msg, sig, pcrs, nonce)
    with pytest.raises(A.AttestError, match="trailing"):
        A.verify_quote(AK, msg + b"\x00", sig, pcrs, nonce)


def test_the_ek_must_be_the_one_pinned_on_site_and_its_certificate_must_chain_to_a_configured_root():
    pin = A.spki_sha256(EK)
    assert A.check_ek(EK, pin, CERT, [ROOT], [ISSUER])["ek_certified"]
    assert A.check_ek(EK, pin, None, [], [])["ek_certified"] is False     # no certificate: the officer's pin alone
    with pytest.raises(A.AttestError, match="officer pinned"):
        A.check_ek(EK, "0" * 64, CERT, [ROOT], [ISSUER])
    with pytest.raises(A.AttestError, match="does not chain"):
        A.check_ek(EK, pin, CERT, [_other_root()], [ISSUER])
    with pytest.raises(A.AttestError, match="no manufacturer roots"):
        A.check_ek(EK, pin, CERT, [], [ISSUER])
    with pytest.raises(A.AttestError, match="validity"):
        A.check_ek(EK, pin, CERT, [ROOT], [ISSUER], at=datetime(1999, 1, 1, tzinfo=timezone.utc))
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(A.AttestError, match="officer pinned|another key"):
        A.check_ek(other, A.spki_sha256(other), CERT, [ROOT], [ISSUER])


def test_make_credential_has_the_tpm_layout_and_binds_the_ak_name():
    ek = A.parse_public(_tss_from_pem())
    idobj, encsec = A.make_credential(ek, AK.name, b"k" * 32, seed=b"s" * 32)
    assert struct.unpack(">H", idobj[:2])[0] == len(idobj) - 2 == 2 + 32 + 2 + 32
    assert struct.unpack(">H", encsec[:2])[0] == 256
    again, _ = A.make_credential(ek, AK.name[:2] + bytes(32), b"k" * 32, seed=b"s" * 32)
    assert again[4:36] != idobj[4:36]                                    # the integrity HMAC covers the AK's name
    assert A.credential_file(idobj, encsec)[:8] == bytes.fromhex("badcc0de00000001")
    with pytest.raises(A.AttestError, match="16 to 32"):
        A.make_credential(ek, AK.name, b"short")


def test_kdfa_matches_its_definition():
    want = __import__("hmac").new(b"k", struct.pack(">I", 1) + b"STORAGE\x00" + b"u" + b"v" + struct.pack(">I", 128),
                                  hashlib.sha256).digest()[:16]
    assert A.kdfa(b"k", b"STORAGE", b"u", b"v", 128) == want


def test_the_quote_nonce_binds_the_signed_request():
    a = A.quote_nonce("E-1", 1000, "n1")
    assert len(a) == 32 and a != A.quote_nonce("E-2", 1000, "n1") != A.quote_nonce("E-1", 1000, "n2")


def _other_root():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "swtpm-localca-rootca")])     # same name, other key
    now = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(now.replace(year=now.year - 1)).not_valid_after(now.replace(year=now.year + 1))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM)


def _tss_from_pem():
    """The EK as a TPMT_PUBLIC (RSA 2048, the TCG default template's shape) from its PEM public key."""
    n = EK.public_numbers().n.to_bytes(256, "big")
    body = (struct.pack(">HHI", A.ALG_RSA, A.ALG_SHA256, 0x000300B2) + struct.pack(">H", 32) + bytes(32)
            + struct.pack(">HHHH", A.ALG_AES, 128, A.ALG_CFB, A.ALG_NULL) + struct.pack(">HI", 2048, 0)
            + struct.pack(">H", 256) + n)
    return body
