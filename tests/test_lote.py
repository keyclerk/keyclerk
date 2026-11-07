# SPDX-License-Identifier: EUPL-1.2
"""Lists of trusted entities (ETSI TS 119 602): verified under pinned signers, cached verbatim, the sequence never
going back (0034 point 7, W0). The lists here are built in the test, in both shapes seen in published lists."""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from keyclerk import lote as L

NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)


def cert(name, key, issuer=None, issuer_key=None, days=365, ca=None, eku=True):
    """A CA when self-signed (basic constraints, keyCertSign), a list signer when issued (id-tsl-kp-tslSigning)."""
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer.subject if issuer else subj)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days)))
    ca = issuer is None if ca is None else ca
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    elif eku:
        b = b.add_extension(x509.ExtendedKeyUsage([L.LIST_SIGNING]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def lote(seq=1, next_update="2027-05-01T00:00:00Z", wrapped=True, status=None):
    svc = {"ServiceName": [{"lang": "en", "value": "PID Issuance"}],
           "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
           "ServiceDigitalIdentity": {"X509Certificates": [{"val": base64.b64encode(b"\x30\x03\x02\x01\x01").decode()}]}}
    if status:
        svc["ServiceStatus"] = status
    body = {"ListAndSchemeInformation": {"LoTEVersionIdentifier": 1, "LoTESequenceNumber": seq,
                                         "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                                         "SchemeTerritory": "EU", "ListIssueDateTime": "2026-11-01T00:00:00Z",
                                         "NextUpdate": next_update},
            "TrustedEntitiesList": [{"TrustedEntityInformation": {"TEName": [{"lang": "en", "value": "PID Provider"}]},
                                     "TrustedEntityServices": [{"ServiceInformation": svc}]}]}
    return json.dumps({"LoTE": body} if wrapped else body).encode()


def jws(payload, key, leaf, **head):
    der = leaf.public_bytes(serialization.Encoding.DER)
    h = {"alg": "ES256", "x5c": [base64.b64encode(der).decode()],
         "x5t#S256": b64u(hashlib.sha256(der).digest()).decode(), **head}
    signing = b64u(json.dumps(h).encode()) + b"." + b64u(payload)
    r, s = decode_dss_signature(key.sign(signing, ec.ECDSA(hashes.SHA256())))
    return signing + b"." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@pytest.fixture
def pki():
    root_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root = cert("Scheme operator signer set", root_key)
    leaf = cert("List signer", leaf_key, root, root_key)
    return root, leaf, leaf_key


def test_a_list_signed_under_a_pinned_signer_reads(pki):
    root, leaf, key = pki
    tl = L.verify(jws(lote(), key, leaf), [root], NOW)
    assert tl.sequence == 1 and tl.territory == "EU" and len(tl.anchors()) == 1
    assert tl.next_update == datetime(2027, 5, 1, tzinfo=timezone.utc)


def test_both_shapes_of_next_update_and_root_read(pki):
    root, leaf, key = pki
    tl = L.verify(jws(lote(next_update={"dateTime": "2027-05-01T00:00:00Z"}, wrapped=False), key, leaf), [root], NOW)
    assert tl.next_update.year == 2027


def test_a_list_from_an_unpinned_signer_is_refused(pki):
    _, leaf, key = pki
    other = cert("Someone else", ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(L.ListRefused, match="pinned signer"):
        L.verify(jws(lote(), key, leaf), [other], NOW)


def test_a_changed_payload_does_not_verify(pki):
    root, leaf, key = pki
    h, _, s = jws(lote(), key, leaf).split(b".")
    with pytest.raises(L.ListRefused, match="signature"):
        L.verify(h + b"." + b64u(lote(seq=9)) + b"." + s, [root], NOW)


def test_alg_none_a_crit_header_and_a_wrong_thumbprint_are_refused(pki):
    root, leaf, key = pki
    with pytest.raises(L.ListRefused, match="not accepted"):
        L.verify(jws(lote(), key, leaf, alg="none"), [root], NOW)
    with pytest.raises(L.ListRefused, match="critical"):
        L.verify(jws(lote(), key, leaf, crit=["b64"]), [root], NOW)
    with pytest.raises(L.ListRefused, match="x5t"):
        L.verify(jws(lote(), key, leaf, **{"x5t#S256": "AAAA"}), [root], NOW)


def test_a_service_whose_status_is_not_granted_gives_no_anchor(pki):
    root, leaf, key = pki
    tl = L.verify(jws(lote(status="http://uri.etsi.org/19602/Status/withdrawn"), key, leaf), [root], NOW)
    assert tl.anchors() == []


def test_the_cache_keeps_the_sequence_from_going_back_and_one_sequence_for_one_list(pki, tmp_path):
    root, leaf, key = pki
    c = L.Cache(tmp_path, [root])
    c.put("pid", jws(lote(seq=2), key, leaf), NOW)
    with pytest.raises(L.ListRefused, match="below"):
        c.put("pid", jws(lote(seq=1), key, leaf), NOW)
    with pytest.raises(L.ListRefused, match="another list"):
        c.put("pid", jws(lote(seq=2, next_update="2027-06-01T00:00:00Z"), key, leaf), NOW)
    assert c.get("pid", NOW).sequence == 2
    c.put("pid", jws(lote(seq=3), key, leaf), NOW)
    assert c.get("pid", NOW).sequence == 3


def test_a_stale_or_swapped_cached_list_counts_as_absent(pki, tmp_path):
    root, leaf, key = pki
    c = L.Cache(tmp_path, [root])
    c.put("pid", jws(lote(seq=2), key, leaf), NOW)
    assert c.get("pid", datetime(2027, 5, 2, tzinfo=timezone.utc)) is None          # past NextUpdate
    (tmp_path / "pid.jws").write_bytes(jws(lote(seq=1), key, leaf))                 # an older one put back by hand
    assert c.get("pid", NOW) is None


def test_garbage_never_raises_anything_but_a_refusal(pki):
    root, *_ = pki
    for bad in (b"", b"a.b", b"a.b.c", b"\xff.\xff.\xff", b"." * 5, b"e30.e30.e30"):
        with pytest.raises(L.ListRefused):
            L.verify(bad, [root], NOW)


JSONISH = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=20),
                       lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=12), c, max_size=4),
                       max_leaves=30)
KEYS = st.sampled_from(["LoTE", "ListAndSchemeInformation", "TrustedEntitiesList", "LoTESequenceNumber",
                        "ListIssueDateTime", "NextUpdate", "TrustedEntityServices", "ServiceInformation",
                        "ServiceDigitalIdentity", "X509Certificates", "val", "TEName", "dateTime"])


@settings(max_examples=300, deadline=None)
@given(st.recursive(JSONISH, lambda c: st.dictionaries(KEYS, c, max_size=5), max_leaves=40))
def test_any_json_parses_or_is_refused(doc):
    """The parser reads input nobody trusts yet: whatever arrives, the answer is a list or a refusal, never a crash."""
    try:
        L.parse(json.dumps(doc).encode())
    except L.ListRefused:
        pass


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=400))
def test_any_bytes_verify_or_are_refused(raw):
    try:
        L.verify(raw, [], NOW)
    except L.ListRefused:
        pass


@pytest.mark.parametrize("bad", [
    {"LoTE": {"ListAndSchemeInformation": {"LoTESequenceNumber": 1, "ListIssueDateTime": "not a time"}}},
    {"LoTE": {"ListAndSchemeInformation": {"LoTESequenceNumber": 1, "ListIssueDateTime": "2026-11-01T00:00:00"}}},
    {"LoTE": {"ListAndSchemeInformation": {"LoTESequenceNumber": 1, "ListIssueDateTime": "2026-11-01T00:00:00Z"},
              "TrustedEntitiesList": [["not", "an", "entity"]]}},
    {"LoTE": {"ListAndSchemeInformation": {"LoTESequenceNumber": 1, "ListIssueDateTime": "2026-11-01T00:00:00Z"},
              "TrustedEntitiesList": [{"TrustedEntityServices": [{"ServiceInformation": {"ServiceDigitalIdentity":
                                                                         {"X509Certificates": [{"val": 5}]}}}]}]}},
    {"LoTE": {"ListAndSchemeInformation": {"LoTESequenceNumber": True, "ListIssueDateTime": "2026-11-01T00:00:00Z"}}},
    {"LoTE": []}, [], "text"])
def test_shapes_it_does_not_expect_are_refusals(bad):
    with pytest.raises(L.ListRefused):
        L.parse(json.dumps(bad).encode())


def test_w1_the_issuer_is_a_ca_and_the_signer_signs_lists(pki):
    """0.29 review W1: a leaf counts only under a pinned CA allowed to sign certificates, and only when it is for
    signing lists (id-tsl-kp-tslSigning); a pinned leaf itself still signs."""
    root, leaf, key = pki
    other_key = ec.generate_private_key(ec.SECP256R1())
    not_ca = cert("A pinned leaf, no CA", other_key, ca=False, eku=True)
    child = cert("Issued by a leaf", key, not_ca, other_key)
    with pytest.raises(L.ListRefused, match="not a CA"):
        L.verify(jws(lote(), key, child), [not_ca], NOW)
    plain_key = ec.generate_private_key(ec.SECP256R1())
    root2 = cert("Signer set 2", plain_key)
    no_eku = cert("Signs anything", key, root2, plain_key, eku=False)
    with pytest.raises(L.ListRefused, match="id-tsl-kp-tslSigning"):
        L.verify(jws(lote(), key, no_eku), [root2], NOW)
    assert L.verify(jws(lote(), plain_key, root2), [root2], NOW).sequence == 1        # the pinned certificate itself


def test_w1_no_one_list_freezes_the_floor(pki, tmp_path):
    root, leaf, key = pki
    with pytest.raises(L.ListRefused, match="whole number"):
        L.verify(jws(lote(seq=2 ** 62), key, leaf), [root], NOW)
    c = L.Cache(tmp_path, [root])
    c.put("pid", jws(lote(seq=5), key, leaf), NOW)
    with pytest.raises(L.ListRefused, match="jumps more than"):
        c.put("pid", jws(lote(seq=5 + L.MAX_STEP + 1), key, leaf), NOW)
    c.put("pid", jws(lote(seq=5 + L.MAX_STEP), key, leaf), NOW)


def test_w2_a_name_stands_for_one_list_and_one_list_for_one_name(pki, tmp_path):
    root, leaf, key = pki
    c = L.Cache(tmp_path, [root])
    c.put("pid", jws(lote(seq=1), key, leaf), NOW)
    with pytest.raises(L.ListRefused, match="one list, one name"):
        c.put("wallets", jws(lote(seq=2), key, leaf), NOW)
    other = lote(seq=2).replace(b"EUPIDProvidersList", b"EUWalletProvidersList")
    with pytest.raises(L.ListRefused, match="holds the list of"):
        c.put("pid", jws(other, key, leaf), NOW)
    assert c.get("PID", NOW).sequence == 1                     # W3: one name whatever its case


def test_w3_shapes_that_once_escaped_are_refusals(pki, tmp_path):
    root, leaf, key = pki
    assert not L.parse(lote(status="http://uri.etsi.org/19602/Svcstatus/notgranted")).anchors()
    good = jws(lote(), key, leaf)
    head, body, sig = good.split(b".")
    for bad_head in (b64u(b"[1, 2]"), b64u(json.dumps({"alg": "ES256", "x5c": [7]}).encode())):
        with pytest.raises(L.ListRefused):
            L.verify(bad_head + b"." + body + b"." + sig, [root], NOW)
    with pytest.raises(L.ListRefused):
        L.parse(b"[" * 100000 + b"]" * 100000)
    c = L.Cache(tmp_path, [root])
    c.put("pid", good, NOW)
    (tmp_path / "floor.json").write_text("{not json")
    with pytest.raises(L.ListRefused, match="restore it"):
        c.put("pid", jws(lote(seq=2), key, leaf), NOW)
