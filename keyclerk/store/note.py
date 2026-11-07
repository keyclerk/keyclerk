"""The change log's checkpoint as a C2SP signed note, for witnesses outside KeyClerk (decision 0022 point 5, roadmap
step 5): c2sp.org/signed-note, tlog-checkpoint and tlog-cosignature, version 1.1.0.

    note        = text + "\\n" + signature lines          text ends in a newline; the last empty line separates them
    line        = "— " + key name + " " + base64(key id (4 bytes) || signature) + "\\n"
    key id      = SHA-256(key name || 0x0A || type || public key)[:4]
    vkey        = key name + "+" + hex(key id) + "+" + base64(type || public key)
    checkpoint  = origin + "\\n" + size (decimal) + "\\n" + base64(root) + "\\n"      KeyClerk writes no extension line

Two signature types, both Ed25519: 0x01, the log's own signature over the text, by the records key under the origin as
its name; 0x04, a witness's cosignature, over "cosignature/v1\\ntime T\\n" + text, the signature carrying the 8-byte
big-endian time T before the 64 signature bytes. The root is the log's RFC 6962 root (keyclerk.store.merkle), so a
witness checks the consistency proofs it already knows. The kc-checkpoint-v1 body stays the store's own record; this
form is what leaves the signer. tests/conformance/c2sp-go.json holds notes and proofs made by Go's implementations
(tools/interop/c2sp), which these functions reproduce byte for byte.
"""
from __future__ import annotations

import base64
import hashlib
import re
import unicodedata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DASH = "—"
LOG, COSIGNATURE = 0x01, 0x04
TYPES = (LOG, COSIGNATURE)
MAX_NOTE = 64 * 1024                    # a checkpoint and some cosignatures; the spec asks for at least 16 signatures
MAX_SIGNATURES = 32
DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")
MAX_TREE = 2 ** 53 - 1                            # the 2026-11-07 custodian review (A1): sizes past it are refused


class NoteRefused(ValueError):
    pass


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    """Canonical standard base64 only (RFC 4648 3.5), as every C2SP decoder must."""
    try:
        b = base64.b64decode(s.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise NoteRefused("not base64") from None
    if b64(b) != s:
        raise NoteRefused("not canonical base64")
    return b


def check_name(name: str) -> str:
    """A key name, origin or cosigner name: 1 to 255 bytes, no space, plus or control character."""
    if not isinstance(name, str) or not 0 < len(name.encode("utf-8")) <= 255 or "+" in name or any(
            c.isspace() or ord(c) < 0x20 or unicodedata.category(c) == "Zs" for c in name):
        raise NoteRefused("a name is 1 to 255 bytes with no space, plus or control character")
    return name


def raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(name: str, kind: int, pub: bytes) -> bytes:
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([kind]) + pub).digest()[:4]


def vkey(name: str, kind: int, pub: bytes) -> str:
    return f"{check_name(name)}+{key_id(name, kind, pub).hex()}+{b64(bytes([kind]) + pub)}"


def parse_vkey(v: str) -> tuple[str, int, bytes]:
    """(name, type, public key) of a vkey whose key id is the one its parts give."""
    parts = v.split("+", 2) if isinstance(v, str) else []          # the name holds no plus; base64 may
    if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{8}", parts[1]):
        raise NoteRefused("a vkey is name+keyid+base64(type || key)")
    name, raw = check_name(parts[0]), unb64(parts[2])
    if len(raw) != 33 or raw[0] not in TYPES:
        raise NoteRefused("a vkey here is an Ed25519 log key (0x01) or Ed25519 cosigner key (0x04)")
    if key_id(name, raw[0], raw[1:]).hex() != parts[1]:
        raise NoteRefused("the vkey's key id is not its name's and key's")
    return name, raw[0], raw[1:]


def checkpoint_text(origin: str, size: int, root: bytes) -> str:
    if len(root) != 32 or size < 1:
        raise NoteRefused("a checkpoint here covers at least one link and has a 32-byte root")
    return f"{check_name(origin)}\n{size}\n{b64(root)}\n"


def parse_checkpoint(text: str) -> tuple[str, int, bytes]:
    """(origin, size, root) of a checkpoint text. Extension lines are refused: KeyClerk writes none, and an Ed25519
    log signature would vouch for lines no witness checks."""
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise NoteRefused("a checkpoint is three lines: origin, size, root (no extension lines)")
    if not DECIMAL.fullmatch(lines[1]):
        raise NoteRefused("the tree size is a decimal with no leading zero")
    if int(lines[1]) > MAX_TREE:                 # every signed number is below 2^53 (edge.MAX_SIGNED_INT): a size past
        raise NoteRefused("the tree size is past 2^53-1: no log of this realm is that large")   # it forges a tree
    root = unb64(lines[2])
    if len(root) != 32:
        raise NoteRefused("the root is 32 bytes")
    return check_name(lines[0]), int(lines[1]), root


def split(note: str) -> tuple[str, list[tuple[str, bytes]]]:
    """The text and the (key name, signature bytes) of each signature line of a note, its shape checked."""
    if not isinstance(note, str) or len(note.encode("utf-8")) > MAX_NOTE:
        raise NoteRefused(f"a note is text of at most {MAX_NOTE} bytes")
    if any(ord(c) < 0x20 and c != "\n" for c in note):
        raise NoteRefused("a note holds no control character but newline")
    cut = note.rfind("\n\n")
    if cut < 0 or not note.endswith("\n"):
        raise NoteRefused("a note is text, an empty line, and signature lines")
    text, sigs = note[:cut + 1], []
    for line in note[cut + 2:-1].split("\n"):
        head, _, rest = line.partition(" ")
        name, _, sig = rest.partition(" ")
        if head != DASH or not sig or " " in sig:
            raise NoteRefused("a signature line is an em dash, a key name and a base64 signature")
        raw = unb64(sig)
        if len(raw) < 5:
            raise NoteRefused("a signature is a key id and a signature")
        sigs.append((check_name(name), raw))
    if not sigs or len(sigs) > MAX_SIGNATURES:
        raise NoteRefused(f"a note has 1 to {MAX_SIGNATURES} signatures")
    return text, sigs


def sign(text: str, name: str, key: Ed25519PrivateKey) -> str:
    """The log's signature line (type 0x01) over text."""
    raw = key_id(name, LOG, raw_public(key)) + key.sign(text.encode("utf-8"))
    return f"{DASH} {check_name(name)} {b64(raw)}\n"


def _cosigned(text: str, t: int) -> bytes:
    return f"cosignature/v1\ntime {t}\n".encode("ascii") + text.encode("utf-8")


def cosign(text: str, name: str, key: Ed25519PrivateKey, t: int) -> str:
    """A witness's cosignature line (type 0x04) over a checkpoint text at POSIX time t."""
    raw = key_id(name, COSIGNATURE, raw_public(key)) + t.to_bytes(8, "big") + key.sign(_cosigned(text, t))
    return f"{DASH} {check_name(name)} {b64(raw)}\n"


def verify(text: str, sigs: list[tuple[str, bytes]], key: tuple[str, int, bytes]) -> int | None:
    """Checks the signatures of one known key (a parsed vkey) on text: None when it has none (signatures of unknown
    keys are ignored, as the spec requires), the cosignature's time (0 for a log signature) when they verify, and a
    refusal when one fails: a note with a bad signature from a known key is rejected whole."""
    name, kind, pub = key
    kid, found = key_id(name, kind, pub), None
    verifier = Ed25519PublicKey.from_public_bytes(pub)
    for n, raw in sigs:
        if n != name or raw[:4] != kid:
            continue
        if kind == LOG:
            msg, sig, t = text.encode("utf-8"), raw[4:], 0
        else:
            if len(raw) != 4 + 8 + 64:
                raise NoteRefused(f"a cosignature of {name} is not 76 bytes")
            t = int.from_bytes(raw[4:12], "big")
            msg, sig = _cosigned(text, t), raw[12:]
        try:
            verifier.verify(sig, msg)
        except InvalidSignature:
            raise NoteRefused(f"the signature of {name} does not verify") from None
        found = t if found is None else max(found, t)
    return found
