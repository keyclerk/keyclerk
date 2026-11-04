# SPDX-License-Identifier: EUPL-1.2
"""The age v1 format a backup is encrypted with (decision 0019): a custodian decrypts one with the standard age tool,
and a file the age tool made decrypts here (a vector it made, and both ways when it is installed)."""
import shutil
import subprocess
from pathlib import Path

import pytest

from keyclerk import age

FIX = Path(__file__).resolve().parent / "fixtures" / "age"
PLAIN = bytes(range(256)) * 273 + b"kc"          # 69890 bytes: two chunks


def _fixture_identity() -> str:
    """Kept as hex, so a secret scanner does not take a test key for a leaked one."""
    return age._b32encode("age-secret-key-", bytes.fromhex((FIX / "identity.hex").read_text().strip())).upper()


def test_a_file_the_age_tool_made_decrypts():
    assert age.decrypt((FIX / "by-age.age").read_bytes(), [_fixture_identity()]) == PLAIN


@pytest.mark.parametrize("size", [0, 1, age.CHUNK - 1, age.CHUNK, age.CHUNK + 1, 2 * age.CHUNK, 150_001])
def test_it_round_trips_to_several_recipients(size):
    a, b = age.keygen(), age.keygen()
    data = bytes(i % 251 for i in range(size))
    blob = age.encrypt(data, [a[1], b[1]])
    assert age.decrypt(blob, [a[0]]) == data and age.decrypt(blob, [b[0]]) == data


def test_another_identity_does_not_open_it():
    blob = age.encrypt(b"x", [age.keygen()[1]])
    with pytest.raises(age.AgeError, match="other recipients"):
        age.decrypt(blob, [age.keygen()[0]])


@pytest.mark.parametrize("where, why", [("payload", "does not authenticate"), ("cut", "does not authenticate"),
                                        ("header", "MAC")])
def test_a_changed_or_cut_file_is_refused(where, why):
    ident, rcpt = age.keygen()
    blob = bytearray(age.encrypt(PLAIN, [rcpt]))
    if where == "payload":
        blob[-100] ^= 1
    elif where == "cut":
        payload = blob.index(b"\n", blob.index(b"---")) + 1
        blob = blob[:payload + 16 + age.CHUNK + age.TAG]      # the first chunk alone: it was not sealed as the last
    else:
        at = blob.index(b"---")
        blob[at:at] = b"-> x-added\n\n"                         # a stanza added to the header, after its MAC
    with pytest.raises(age.AgeError, match=why):
        age.decrypt(bytes(blob), [ident])


def test_a_recipient_is_its_identity_public_key():
    ident, rcpt = age.keygen()
    assert age.recipient(ident) == rcpt and rcpt.startswith("age1") and ident.startswith("AGE-SECRET-KEY-1")
    with pytest.raises(age.AgeError, match="checksum"):
        age._recipient(rcpt[:-1] + ("q" if rcpt[-1] != "q" else "p"))


@pytest.mark.skipif(not shutil.which("age"), reason="the age tool is not installed")
def test_both_ways_with_the_age_tool(tmp_path):
    ident, rcpt = age.keygen()
    (tmp_path / "id").write_text(ident + "\n")
    (tmp_path / "x.age").write_bytes(age.encrypt(PLAIN, [rcpt]))
    out = subprocess.run(["age", "-d", "-i", str(tmp_path / "id"), str(tmp_path / "x.age")], capture_output=True,
                         check=True)
    assert out.stdout == PLAIN
    (tmp_path / "p").write_bytes(PLAIN)
    subprocess.run(["age", "-r", rcpt, "-o", str(tmp_path / "y.age"), str(tmp_path / "p")], check=True)
    assert age.decrypt((tmp_path / "y.age").read_bytes(), [ident]) == PLAIN
