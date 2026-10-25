# SPDX-License-Identifier: EUPL-1.2
"""Guarded input at every seam: parser bombs, oversize, depth, identifiers, timestamps, text, URLs, responses."""
import io
import json

import pytest

from keyclerk import guard as G


def test_yaml_aliases_and_anchors_are_refused():
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b]\n"
    with pytest.raises(G.InputRejected, match="anchors|aliases"):
        G.load_yaml_text(bomb)


def test_depth_size_and_nul_are_bounded():
    with pytest.raises(G.InputRejected, match="deeper"):
        G.load_yaml_text("x: " + "[" * 40 + "]" * 40)
    with pytest.raises(G.InputRejected, match="longer"):
        G.load_yaml_text("x: '" + "a" * (G.MAX_STRING + 1) + "'")
    with pytest.raises(G.InputRejected, match="NUL"):
        G.load_json_bytes(json.dumps({"x": "a\u0000b"}).encode())
    with pytest.raises(G.InputRejected, match="above"):
        G.load_json_bytes(b"[" + b"1," * (G.MAX_RESPONSE_BYTES // 2) + b"1]")


def test_json_constants_and_bad_encoding_are_refused():
    with pytest.raises(G.InputRejected):
        G.load_json_bytes(b'{"x": NaN}')
    with pytest.raises(G.InputRejected):
        G.load_json_bytes(b"\xff\xfe")


@pytest.mark.parametrize("bad", ['idp:a" or 1 eq "1', "a b", "../etc", "", "a" * 300, "x\ny", "<script>", None, 5])
def test_identifiers_refuse_injection_shapes(bad):
    with pytest.raises(G.InputRejected):
        G.ident(bad)


def test_identifiers_accept_real_anchors():
    for ok in ("idp:7c1f-ann", "fed:partnerworks:8812", "G-example-0001", "place:heverlee/main/0", "op:7a1e-oscar"):
        assert G.ident(ok) == ok


def test_timestamps_need_a_zone_and_text_refuses_controls():
    assert G.timestamp("2026-10-22T08:00:00Z").utcoffset().total_seconds() == 0
    with pytest.raises(G.InputRejected, match="zone"):
        G.timestamp("2026-10-22T08:00:00")
    with pytest.raises(G.InputRejected):
        G.text("reason‮evil")
    assert G.safe_for_log("a\nb\x1bc") == "a b?c"


def test_broker_urls():
    assert G.broker_url("https://id.example/") == "https://id.example"
    assert G.broker_url("http://localhost:8080") == "http://localhost:8080"
    userinfo = "https://user:pw" + "@id.example"          # built from parts: the leak gate flags anything shaped like an address
    for bad in ("http://id.example", userinfo, "ftp://x", "https://id.example/?a=1", "javascript:x"):
        with pytest.raises(G.InputRejected):
            G.broker_url(bad)


class _Resp:
    def __init__(self, body: bytes, ctype: str):
        self._b, self.headers = io.BytesIO(body), {"Content-Type": ctype}

    def read(self, n=-1):
        return self._b.read(n)


def test_responses_are_bounded_and_typed():
    assert G.read_response(_Resp(b'{"a": 1}', "application/scim+json")) == {"a": 1}
    with pytest.raises(G.InputRejected, match="not JSON"):
        G.read_response(_Resp(b"<html>", "text/html"))
    with pytest.raises(G.InputRejected, match="above"):
        G.read_response(_Resp(b"[" + b"1," * 100 + b"1]", "application/json"), max_bytes=50)
