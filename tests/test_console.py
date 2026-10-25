# SPDX-License-Identifier: EUPL-1.2
"""The console renders every view read-only from the records and the reconciler's state, and escapes what it shows."""
import json
from pathlib import Path

from keyclerk.console import Console

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_every_view_renders(tmp_path):
    (tmp_path / "observed.json").write_text(json.dumps([["/groups/office-staff", "idp:91d0-bert"]]), encoding="utf-8")
    (tmp_path / "runs.jsonl").write_text(json.dumps({"at": "2026-10-22T08:00:00+00:00", "add": [], "remove": [],
                                                     "seconds": 0.1}) + "\n", encoding="utf-8")
    c = Console(FIXTURES / "records.yaml", tmp_path)
    for path in ("/", "/people", "/groups", "/delegations", "/situation", "/runs"):
        code, text = c.page(path, {})
        assert code == 200 and "could not be built" not in text, path
    code, text = c.page("/explain", {"anchor": ["idp:55bb-eva"], "group": ["/groups/office-staff"]})
    assert "site-heverlee" in text                                              # the path through the include
    assert c.page("/nowhere", {})[0] == 404


def test_what_it_shows_is_escaped(tmp_path):
    c = Console(FIXTURES / "records.yaml", tmp_path)
    code, text = c.page("/explain", {"anchor": ["<script>x</script>"], "group": ["/grants/x"]})
    assert "<script>x</script>" not in text and "Not a valid person and group" in text


# --- the HTTP seam ------------------------------------------------------------------------------------------------

import base64
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keyclerk import console as C
from keyclerk.guard import InputRejected
from keyclerk.oidc import Oidc


def _serve(tmp_path, auth=None):
    c = Console(FIXTURES / "records.yaml", tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), C.handler(c, auth, {"good.host"}, False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _get(url, host="good.host", method="GET", cookie=None):
    req = urllib.request.Request(url, method=method, headers={"Host": host, **({"Cookie": cookie} if cookie else {})})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_unknown_hosts_and_writes_are_refused_and_headers_are_strict(tmp_path):
    srv, base = _serve(tmp_path)
    try:
        assert _get(base + "/", host="evil.example")[0] == 400                 # no DNS rebinding
        assert _get(base + "/", method="POST")[0] == 405
        code, headers, _ = _get(base + "/")
        assert code == 200 and "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert headers.get("X-Frame-Options") == "DENY" and _get(base + "/" + "a" * 3000)[0] == 414
    finally:
        srv.shutdown()


def _oidc():
    return Oidc(public_issuer="http://127.0.0.1:1/realms/r", internal_issuer="http://localhost:1/realms/r",
                client_id="keyclerk-console", redirect_uri="http://127.0.0.1:2/callback", viewer_role="keyclerk-viewer")


def test_without_a_session_every_page_sends_to_sign_in_and_a_tampered_cookie_is_refused(tmp_path):
    auth = _oidc()
    srv, base = _serve(tmp_path, auth)
    try:
        code, headers, _ = _get(base + "/people")
        assert code == 302 and headers["Location"] == "/login"
        code, headers, _ = _get(base + "/login")
        assert code == 302 and "code_challenge_method=S256" in headers["Location"]
        good = auth.session({"sub": "u1", "name": "ann", "roles": ["keyclerk-viewer"]})
        assert _get(base + "/people", cookie=f"{C.COOKIE}={good}")[0] == 200
        plain = auth.session({"sub": "u2", "name": "bob", "roles": []})
        assert _get(base + "/people", cookie=f"{C.COOKIE}={plain}")[0] == 403                 # signed in, not a viewer
        assert _get(base + "/people", cookie=C.COOKIE + "=é.é")[0] == 302          # not ASCII: anonymous
        body, sig = good.rsplit(".", 1)
        forged = base64.urlsafe_b64encode(b'{"sub":"x","exp":9999999999}').rstrip(b"=").decode() + "." + sig
        assert _get(base + "/people", cookie=f"{C.COOKIE}={forged}")[0] == 302
        assert _get(base + "/callback?code=x&state=unknown")[0] == 400
        for _ in range(1100):                                                       # flooding evicts, never blocks
            auth.login()
        assert len(auth.flows) <= 1000 and auth.login()[0].startswith("http")
    finally:
        srv.shutdown()


def test_tokens_are_verified_by_signature_issuer_expiry_and_client():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    auth = _oidc()
    auth.jwks = {"k1": {"kid": "k1", "kty": "RSA", "n": b64(nums.n.to_bytes(256, "big")), "e": b64(nums.e.to_bytes(3, "big"))}}
    auth.jwks_at = time.time()

    def jwt(claims, k=key, alg="RS256"):
        h = b64(json.dumps({"alg": alg, "kid": "k1"}).encode())
        p = b64(json.dumps(claims).encode())
        s = b64(k.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256()))
        return f"{h}.{p}.{s}"

    ok = {"iss": "http://localhost:1/realms/r", "exp": time.time() + 300, "azp": "keyclerk-console", "sub": "u1"}
    assert auth.verify(jwt(ok))["sub"] == "u1"
    for bad in ({**ok, "iss": "http://evil/realms/r"}, {**ok, "exp": time.time() - 100}, {**ok, "azp": "other"}):
        with pytest.raises(InputRejected):
            auth.verify(jwt(bad))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(Exception, match="signature"):
        auth.verify(jwt(ok, k=other))
    with pytest.raises(Exception, match="algorithm"):
        auth.verify(jwt(ok, alg="none"))
