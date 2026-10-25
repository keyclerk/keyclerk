# SPDX-License-Identifier: EUPL-1.2
"""Sign-in for KeyClerk's own pages and its API: OpenID Connect authorization code with PKCE against the broker, and
bearer tokens for front ends built by others.

The page never sees a password. Tokens are verified here (RS256 against the broker's published keys, issuer, expiry,
issued-at and authorised party). A browser holds only a short session cookie, signed with a per-process key, HttpOnly
and SameSite, carrying who signed in (subject, name, anchor), their roles and a CSRF token for writes. A sign-in in
flight is bound to the browser that started it (a flow cookie), and the table of flows in flight is bounded by
evicting the oldest, so nobody can fill it to stop others signing in. Two issuer URLs exist because a browser
and the server may reach the broker by different names (a published port and a pod-local name); a token from either
is accepted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field

from keyclerk import guard

SESSION_SECONDS = 900          # short: a removed role is felt within minutes; the broker's SSO re-signs silently
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"
MAX_LOGOUT_BODY = 16 * 1024
MAX_REVOKED = 100000
FLOW_SECONDS = 300
MAX_FLOWS = 1000


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def rs256(jwt: str, key_for) -> dict:
    """The claims of a JWT whose RS256 signature verifies with the JWK key_for(kid) returns; InputRejected otherwise.
    Shared by sign-in and by approval proofs (keyclerk.approvals)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    guard.text(jwt, "token", 16384)
    try:
        h64, p64, s64 = jwt.split(".")
        header, claims = json.loads(_b64d(h64)), json.loads(_b64d(p64))
    except ValueError as e:
        raise guard.InputRejected("malformed token") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise guard.InputRejected("malformed token")
    if header.get("alg") != "RS256":
        raise guard.InputRejected("token algorithm not accepted")
    k = key_for(str(header.get("kid", ""))[:200])
    try:
        pub = rsa.RSAPublicNumbers(int.from_bytes(_b64d(k["e"]), "big"), int.from_bytes(_b64d(k["n"]), "big")).public_key()
        pub.verify(_b64d(s64), f"{h64}.{p64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:   # noqa: BLE001
        raise guard.InputRejected("token signature does not verify") from e
    return claims


def _roles(claims: dict, client_id: str) -> list[str]:
    raw = set((claims.get("realm_access") or {}).get("roles", [])) | \
        set(((claims.get("resource_access") or {}).get(client_id) or {}).get("roles", []))
    out = []
    for r in raw:
        try:
            out.append(guard.ident(r, "role"))
        except guard.InputRejected:
            continue
    return sorted(out)[:64]


def _anchor(claims: dict) -> str | None:
    try:
        return guard.anchor(claims["anchor"]) if claims.get("anchor") else None
    except guard.InputRejected:
        return None


@dataclass
class Oidc:
    public_issuer: str                 # as the browser reaches the broker, e.g. https://id.example/realms/r
    internal_issuer: str               # as this server reaches it
    client_id: str
    redirect_uri: str
    viewer_role: str
    key: bytes = field(default_factory=lambda: os.urandom(32))
    flows: OrderedDict = field(default_factory=OrderedDict)
    jwks: dict = field(default_factory=dict)
    jwks_at: float = 0.0
    approval_acr: str | None = None
    revoked: OrderedDict = field(default_factory=OrderedDict)    # ("sub" | "sid", value) -> when the broker ended it
    resolve: object = None             # claims -> the person as the records name them (decision 0028), set by the desk

    def anchor_of(self, *claim_sets: dict) -> str | None:
        """The person a token names: through the store's mapping on the change log (anchors.resolve, two phases), the
        anchor claim as it is on the signed YAML store. The first claim set that names someone wins."""
        for claims in claim_sets:
            got = self.resolve(claims) if self.resolve else _anchor(claims)
            if got:
                return got
        return None
    seen_jti: OrderedDict = field(default_factory=OrderedDict)

    def __post_init__(self):
        for u in (self.public_issuer, self.internal_issuer, self.redirect_uri):
            guard.broker_url(u.split("/realms/")[0] if "/realms/" in u else u.rsplit("/", 1)[0])
        guard.name(self.client_id, "client")
        guard.ident(self.viewer_role, "viewer role")

    # --- the flow -------------------------------------------------------------------------------------------------

    def login(self, nonce: str | None = None, purpose: dict | None = None, fresh: bool = False) -> tuple[str, str]:
        """(the broker URL to send the browser to, the flow cookie value that binds the flow to this browser).
        With a nonce and a purpose (an approval), the person must sign in again (prompt=login, max_age=0) and the
        broker signs that nonce into the ID token: the approval proof (keyclerk.approvals, decision 0006)."""
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        nonce = nonce or secrets.token_urlsafe(16)
        self._expire_flows()
        while len(self.flows) >= MAX_FLOWS:
            self.flows.popitem(last=False)          # the oldest flow in flight goes, never a refusal of new ones
        self.flows[state] = (verifier, nonce, time.time(), purpose)
        challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
        q = {"client_id": self.client_id, "response_type": "code", "scope": "openid", "redirect_uri": self.redirect_uri,
             "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
        if purpose or fresh:                               # an approval, or a fresh sign-in to take a secret (0014b)
            q.update({"prompt": "login", "max_age": "0"})
            if self.approval_acr:                          # the level the realm binds to a passkey (decision 0006)
                q["acr_values"] = self.approval_acr
                q["claims"] = json.dumps({"id_token": {"acr": {"essential": True, "values": [self.approval_acr]}}})
        return f"{self.public_issuer}/protocol/openid-connect/auth?{urllib.parse.urlencode(q)}", self._sign(state)

    def logout_url(self) -> str:
        """Ends the broker's session too, so the next sign-in may be someone else; back to this page after."""
        back = self.redirect_uri.rsplit("/", 1)[0] + "/"
        q = {"client_id": self.client_id, "post_logout_redirect_uri": back}
        return f"{self.public_issuer}/protocol/openid-connect/logout?{urllib.parse.urlencode(q)}"

    def login_url(self) -> str:
        return self.login()[0]

    def _expire_flows(self):
        now = time.time()
        while self.flows and now - next(iter(self.flows.values()))[2] > FLOW_SECONDS:
            self.flows.popitem(last=False)

    def callback(self, code: str, state: str, flow_cookie: str | None = None) -> str:
        """Exchange the code; return a session cookie value. The flow cookie must name this state (no login CSRF)."""
        purpose, value = self.complete(code, state, flow_cookie)
        if purpose:
            raise guard.InputRejected("this flow was an approval, not a sign-in")
        return value

    def complete(self, code: str, state: str, flow_cookie: str | None = None) -> tuple[dict | None, str | dict]:
        """(None, a session cookie value) for a sign-in; (the purpose, {"id_token", "claims"}) for an approval."""
        guard.text(code, "code", 2048)
        guard.text(state, "state", 200)
        if flow_cookie is not None and self._unsign(flow_cookie) != state:
            raise guard.InputRejected("sign-in started in another browser")
        flow = self.flows.pop(state, None)
        if not flow or time.time() - flow[2] > FLOW_SECONDS:
            raise guard.InputRejected("unknown or expired sign-in")
        verifier, nonce, _, purpose = flow
        data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "client_id": self.client_id,
                                       "redirect_uri": self.redirect_uri, "code_verifier": verifier}).encode()
        with urllib.request.urlopen(urllib.request.Request(f"{self.internal_issuer}/protocol/openid-connect/token",
                                                           data=data), timeout=30) as r:
            body = guard.read_response(r)
        claims = self.verify(body.get("access_token", ""))
        idc = self.verify(body.get("id_token", ""), audience=self.client_id)
        if idc.get("nonce") != nonce:
            raise guard.InputRejected("nonce mismatch")
        if purpose:
            return purpose, {"id_token": body.get("id_token", ""), "claims": idc}
        return None, self.session({"sid": guard.text(str(idc.get("sid", "")), "sid", 200),
                                   "sub": guard.text(str(claims.get("sub", "")), "sub", 200),
                             "name": guard.text(str(idc.get("preferred_username", "")), "name", 200),
                             "auth_time": int(idc["auth_time"]) if isinstance(idc.get("auth_time"), (int, float)) else 0,
                             "anchor": self.anchor_of(idc, claims), "roles": _roles(claims, self.client_id)})

    # --- tokens ---------------------------------------------------------------------------------------------------

    def _keys(self, kid: str) -> dict:
        if kid not in self.jwks or time.time() - self.jwks_at > 600:
            if time.time() - self.jwks_at < 10 and self.jwks:
                raise guard.InputRejected("token signed by an unknown key")   # no refetch storm on unknown kids
            with urllib.request.urlopen(f"{self.internal_issuer}/protocol/openid-connect/certs", timeout=30) as r:
                body = guard.read_response(r)
            self.jwks = {k["kid"]: k for k in body.get("keys", []) if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"}
            self.jwks_at = time.time()
        if kid not in self.jwks:
            raise guard.InputRejected("token signed by an unknown key")
        return self.jwks[kid]

    def verify(self, jwt: str, audience: str | None = None, clients: tuple[str, ...] | None = None) -> dict:
        claims = rs256(jwt, self._keys)
        now = time.time()
        if claims.get("iss") not in (self.public_issuer, self.internal_issuer):
            raise guard.InputRejected("token from another issuer")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - 30:
            raise guard.InputRejected("token expired")
        if isinstance(claims.get("iat"), (int, float)) and claims["iat"] > now + 60:
            raise guard.InputRejected("token issued in the future")
        if audience:
            aud = claims.get("aud")
            if audience not in (aud if isinstance(aud, list) else [aud]):
                raise guard.InputRejected("token for another audience")
        elif claims.get("azp") not in (clients or (self.client_id,)):
            raise guard.InputRejected("token for another client")
        return claims

    def bearer(self, token: str, clients: tuple[str, ...]) -> dict:
        """Who calls the API with a bearer token from one of the allowed clients (front ends built by others)."""
        claims = self.verify(token, clients=clients)
        if claims.get("typ") not in ("Bearer", "DPoP") or "nonce" in claims:
            raise guard.InputRejected("not an access token")    # an ID token (an approval proof) never acts as anyone
        return {"sub": guard.text(str(claims.get("sub", "")), "sub", 200),
                "name": guard.text(str(claims.get("preferred_username", "")), "name", 200),
                "anchor": self.anchor_of(claims), "roles": _roles(claims, str(claims.get("azp"))), "csrf": None,
                "azp": str(claims.get("azp")), "cnf_jkt": (claims.get("cnf") or {}).get("jkt") if isinstance(claims.get("cnf"), dict) else None}

    # --- the session ----------------------------------------------------------------------------------------------

    def _sign(self, body: str) -> str:
        return body + "." + _b64e(hmac.new(self.key, body.encode(), hashlib.sha256).digest())

    def _unsign(self, value: str | None) -> str | None:
        if not value or len(value) > 4096 or "." not in value:
            return None
        body, sig = value.rsplit(".", 1)
        try:
            good = hmac.compare_digest(sig.encode("ascii"),
                                       _b64e(hmac.new(self.key, body.encode(), hashlib.sha256).digest()).encode())
        except (UnicodeEncodeError, TypeError):
            return None                     # a cookie that is not ASCII is simply not a session
        return body if good else None

    # --- back-channel logout (OpenID Connect Back-Channel Logout 1.0) ----------------------------------------------

    def backchannel(self, logout_token: str) -> None:
        """The broker says a session ended: every session of this desk for that person (sub) or that broker session
        (sid), issued before now, ends too. The token is a JWT the broker signed; replays are refused."""
        claims = rs256(logout_token, self._keys)
        now = time.time()
        if claims.get("iss") not in (self.public_issuer, self.internal_issuer):
            raise guard.InputRejected("logout token from another issuer")
        aud = claims.get("aud")
        if self.client_id not in (aud if isinstance(aud, list) else [aud]):
            raise guard.InputRejected("logout token for another client")
        if not isinstance(claims.get("events"), dict) or BACKCHANNEL_EVENT not in claims["events"] or "nonce" in claims:
            raise guard.InputRejected("not a logout token")
        if not isinstance(claims.get("iat"), (int, float)) or not now - 300 <= claims["iat"] <= now + 60:
            raise guard.InputRejected("logout token too old or from the future")
        jti = str(claims.get("jti") or "")
        if not jti or jti in self.seen_jti:
            raise guard.InputRejected("logout token replayed")
        sub, sid = claims.get("sub"), claims.get("sid")
        if not sub and not sid:
            raise guard.InputRejected("logout token names no one")
        self.seen_jti[jti] = now
        for key in (("sub", sub), ("sid", sid)):
            if key[1]:
                self.revoked[(key[0], str(key[1])[:200])] = now
                self.revoked.move_to_end((key[0], str(key[1])[:200]))
        for table in (self.revoked, self.seen_jti):          # older than a session's life: nothing left to end
            while table and (now - next(iter(table.values())) > SESSION_SECONDS + 60 or len(table) > MAX_REVOKED):
                table.popitem(last=False)

    def _ended(self, who: dict) -> bool:
        for key in (("sub", who.get("sub")), ("sid", who.get("sid"))):
            t = self.revoked.get((key[0], str(key[1]))) if key[1] else None
            if t is not None and who.get("iat", 0) <= t:
                return True
        return False

    def session(self, who: dict) -> str:
        payload = {**who, "csrf": secrets.token_urlsafe(18), "iat": time.time(), "exp": int(time.time()) + SESSION_SECONDS}
        return self._sign(_b64e(json.dumps(payload).encode()))

    def who(self, cookie: str | None) -> dict | None:
        body = self._unsign(cookie)
        if body is None:
            return None
        try:
            who = json.loads(_b64d(body))
        except ValueError:
            return None
        if not isinstance(who, dict) or who.get("exp", 0) <= time.time() or self._ended(who):
            return None
        return who


def backchannel_post(auth, headers, rfile) -> int:
    """The HTTP side of a back-channel logout, shared by the desk and the console: a small form body with one
    logout_token; 200 when it ended sessions, 400 otherwise (never why)."""
    ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    try:
        n = int(headers.get("Content-Length") or "0")
    except ValueError:
        return 400
    if auth is None or ctype != "application/x-www-form-urlencoded" or not 0 < n <= MAX_LOGOUT_BODY:
        return 400
    raw = rfile.read(n)
    try:
        q = urllib.parse.parse_qs(raw.decode("ascii"), max_num_fields=5, strict_parsing=True)
        auth.backchannel(q["logout_token"][0])
    except Exception:   # noqa: BLE001 - a bad logout token says nothing back
        return 400
    return 200

