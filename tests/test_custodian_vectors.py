# SPDX-License-Identifier: EUPL-1.2
"""The custodian's conformance vectors (decision 0033 point 9) are what tools/gen_custodian_conformance.py writes, and
the Python reference agrees with every step that has a counterpart in it: the store's structural check for links, the
canonical bytes every signed object must be, the checkpoint body's shape, and note.parse_checkpoint for notes. The Go
custodian replays the same file (cmd/keyclerk-custodian/vectors_test.go). A step the Go side refuses and Python would
take is a broken contract (the 2026-11-07 review's differential finding)."""
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from keyclerk import edge as E
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store import note as N

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "conformance" / "custodian.json"
CUSTODIAN_ONLY = ("one body per position", "more than 500", "root or head", "over 1 links", "origin",
                  "not a statement")   # the custodian's own state, not a property of the bytes


def test_the_vectors_are_the_generators():
    before = VECTORS.read_bytes()
    subprocess.run([sys.executable, str(ROOT / "tools" / "gen_custodian_conformance.py")], check=True,
                   capture_output=True)
    assert VECTORS.read_bytes() == before, "regenerate tests/conformance/custodian.json"


def steps():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_python_refuses_every_byte_level_refusal_the_custodian_makes():
    v = steps()
    for s in v["steps"]:
        refused = s.get("refused", "")
        if not refused or any(c in refused for c in CUSTODIAN_ONLY):
            continue
        data = base64.b64decode(s["data"])
        label, _, raw = data.partition(b"\n")
        with pytest.raises((ValueError, TypeError), match=""):
            if label == L.LINK_FORMAT.encode():
                L.follows(L._body(E._parse(raw)), v["realm"], 10**6, None, 1)   # the bytes alone, not the position
            elif label == L.CHECKPOINT_FORMAT.encode():
                L.open_checkpoint({"bytes": base64.b64encode(raw).decode(), "signature": "0" * 128}, "0" * 64)
            else:
                N.parse_checkpoint(data.decode("utf-8"))
            raise AssertionError(f"Python took a step the custodian refuses: {s['name']}")


def test_the_store_agrees_with_every_structural_link_step():
    v = steps()
    size, head, fence = 0, None, 1
    for s in v["steps"]:
        data = base64.b64decode(s["data"])
        if not data.startswith(L.LINK_FORMAT.encode() + b"\n"):
            continue
        raw = data.split(b"\n", 1)[1]
        refused = s.get("refused", "")
        if refused and any(c in refused for c in CUSTODIAN_ONLY if c != "one body per position"):
            continue                                                      # the signer's cap, not the store's
        if refused:
            with pytest.raises((ValueError, TypeError)):
                L.follows(L._body(E._parse(raw)), v["realm"], size, head, fence)
            continue
        body = E._parse(raw)
        if body["seq"] < size:
            continue                                                      # the same body again
        L.follows(L._body(body), v["realm"], size, head, fence)
        head = merkle.leaf(data + bytes.fromhex(s["signature"]))
        size, fence = size + 1, body["fence"]
