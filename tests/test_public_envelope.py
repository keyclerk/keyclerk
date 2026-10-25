# SPDX-License-Identifier: EUPL-1.2
"""The edge protocol repository's section 4 reader (docs/public/edge-protocol/tools/envelope.py, fuzzed there) against
the engine's own: on every sealed bundle in the conformance set, and on random signed bytes. The reader may be no
looser than the engine, and must accept every bundle the engine's verifier accepts."""
import base64
import importlib.util
import json
from pathlib import Path

from hypothesis import given, settings, strategies as st

from keyclerk import edge as E

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("envelope", ROOT / "docs/public/edge-protocol/tools/envelope.py")
envelope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(envelope)
SET = json.loads((ROOT / "tests/conformance/edge.json").read_text(encoding="utf-8"))


def _verify(key, sig, raw) -> bool:
    return E._verifies(key, sig, raw)


def _reader(sealed, key):
    try:
        return envelope.read_sealed(sealed, E.BUNDLE_FORMAT, key, _verify)
    except ValueError:
        return None


def _engine(sealed, key):
    try:
        return E.unseal(sealed, key, E.BUNDLE_FORMAT)
    except ValueError:
        return None


def test_the_reader_agrees_with_the_engine_on_every_conformance_bundle():
    for c in SET["verifier"]["cases"]:
        key = c["pins"]["bundle_key"]
        mine, theirs = _reader(c["sealed"], key), _engine(c["sealed"], key)
        if mine is not None:
            assert theirs == mine, c["name"]                    # never looser than the engine
        if c["expected"]["ok"]:
            assert mine is not None, c["name"]                  # never refuses what the verifier accepts


@settings(max_examples=400, deadline=None)
@given(st.binary(max_size=300))
def test_on_random_signed_bytes_the_reader_is_never_looser(raw):
    accepted = None
    try:
        accepted = envelope.parse_canonical(raw)
    except ValueError:
        pass
    if accepted is not None:
        assert E._parse(raw) == accepted


@settings(max_examples=300, deadline=None)
@given(st.recursive(st.none() | st.booleans() | st.integers(0, 2 ** 53 - 1) | st.text(max_size=8),
                    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=6), inner, max_size=4),
                    max_leaves=12))
def test_canonical_bytes_read_back_the_same_in_both(value):
    body = {"format": E.BUNDLE_FORMAT, "key_id": envelope.key_id("11" * 32), "x": value}
    raw = envelope.canonical(body)
    assert raw == E.canonical(body)
    assert envelope.parse_canonical(raw) == E._parse(raw) == body
    assert envelope.decode_base64(base64.b64encode(raw).decode()) == raw
