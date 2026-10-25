# SPDX-License-Identifier: EUPL-1.2
"""The KeyClerk API and the bundled front end (decision 0005).

/api/v1 is the contract every front end uses (schema/api.openapi.json); the bundled front end (keyclerk/ui) is a static
page that calls nothing else, so anything it does, another front end can do. Two ways in:
  a browser session   /login and /callback sign in at the broker (PKCE); the session cookie is HttpOnly and SameSite,
                      and every POST carries the CSRF token from /api/v1/me in the X-KeyClerk-CSRF header
  a bearer token      a front end with its own broker client sends its user's access token; the client must be named
                      with --api-client
Every request body is bounded, must be JSON and is validated against the contract before the desk sees it; every
answer has the same strict headers; errors share one shape. The route table below and the contract are held equal
by tests. Connections are bounded and idle ones dropped (keyclerk.httpserve); a burst waits briefly for a free worker
before it is told the desk is busy.

    python -m keyclerk.api --config keyclerk.yaml --store /var/lib/keyclerk-desk --signing-key /run/secrets/records.key
        [--seed records.yaml] [--broker-state /var/lib/keyclerk] --oidc-public-issuer https://id.example/realms/r
        --oidc-redirect https://desk.example/callback [--allowed-host desk.example] [--api-client other-front-end]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from collections import deque
from functools import lru_cache
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from keyclerk import config, guard
from keyclerk.httpserve import BUSY_WAIT_SECONDS, SOCKET_SECONDS, Server
from keyclerk.console import COOKIE, FLOW_COOKIE, parse_cookies
from keyclerk.signer import SignerRefused
from keyclerk.desk import Desk, Refusal, Throttled

UI = Path(__file__).resolve().parent / "ui"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/personkey.js": ("personkey.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/vendor/cytoscape.min.js": ("vendor/cytoscape.min.js", "text/javascript; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml"), "/favicon.ico": ("favicon.ico", "image/x-icon"),
          "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),     # brand/build_icons.py
          "/mark-light.svg": ("mark-light.svg", "image/svg+xml"), "/mark-dark.svg": ("mark-dark.svg", "image/svg+xml")}
MAX_BODY = 64 * 1024
MAX_CONCURRENT = 16                   # requests worked on at once
PER_PERSON = 4                        # of which one signed-in person (or one API client's user) may hold
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
HEADERS = (("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
           ("X-Frame-Options", "DENY"), ("Cross-Origin-Opener-Policy", "same-origin"),
           ("Cross-Origin-Resource-Policy", "same-origin"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))

# method, contract path, desk call; the contract (schema/api.openapi.json) holds the same set (tests)
ROUTES = [
    ("GET", "/me", lambda d, w, p, b: d.me(w)),
    ("GET", "/people", lambda d, w, p, b: d.people(w)),
    ("GET", "/people/{anchor}", lambda d, w, p, b: d.person(w, p["anchor"])),
    ("GET", "/people/{anchor}/graph", lambda d, w, p, b: d.person_graph(w, p["anchor"], p.get("at"))),
    ("GET", "/groups", lambda d, w, p, b: d.groups(w)),
    ("GET", "/groups/{group_id}", lambda d, w, p, b: d.group(w, p["group_id"])),
    ("GET", "/delegations", lambda d, w, p, b: d.delegations(w)),
    ("GET", "/delegations/tree", lambda d, w, p, b: d.delegation_tree(w, p.get("at"))),
    ("GET", "/visits", lambda d, w, p, b: d.visits(w)),
    ("GET", "/visits/{visit_id}", lambda d, w, p, b: d.visit_detail(w, p["visit_id"], p.get("at"))),
    ("GET", "/visits/{visit_id}/qr/{party}", lambda d, w, p, b: d.visit_qr(w, p["visit_id"], p["party"])),
    ("GET", "/scan/{token}", lambda d, w, p, b: d.scan(p["token"])),             # public, served before sign-in (below)
    ("GET", "/qr-key", lambda d, w, p, b: d.qr_key()),                            # public, served before sign-in (below)
    ("GET", "/changes", lambda d, w, p, b: d.changes(w)),
    ("POST", "/changes", lambda d, w, p, b: d.propose(w, b)),
    ("POST", "/changes/preview", lambda d, w, p, b: d.preview(w, b)),
    ("GET", "/changes/{change_id}/statement", lambda d, w, p, b: d.statement(w, p["change_id"])),
    ("GET", "/changes/{change_id}/phone-link", lambda d, w, p, b: d.phone_link(w, p["change_id"])),
    ("POST", "/changes/{change_id}/approve", lambda d, w, p, b: d.approve(w, p["change_id"], (b or {}).get("proof"))),
    ("POST", "/changes/{change_id}/approval-sign-in", lambda d, w, p, b: d.statement(w, p["change_id"])),
    ("POST", "/changes/{change_id}/withdraw", lambda d, w, p, b: d.withdraw(w, p["change_id"])),
    ("GET", "/broker", lambda d, w, p, b: d.broker(w)),
    # decision 0014: what a person and an edge's officer do
    ("GET", "/me/keys", lambda d, w, p, b: d.my_keys(w)),
    ("GET", "/relay", lambda d, w, p, b: d.relay_list(w)),
    ("POST", "/relay/{relay_id}/take", lambda d, w, p, b: d.relay_take(w, p["relay_id"])),
    ("POST", "/relay/{relay_id}/confirm", lambda d, w, p, b: d.relay_confirm(w, p["relay_id"])),
    ("GET", "/edge/evidence", lambda d, w, p, b: d.edge_evidence_head(w["edge"])),
    ("GET", "/edge/escrow/{item_id}", lambda d, w, p, b: d.edge_escrow_status(w["edge"], p["item_id"])),
    ("GET", "/edges", lambda d, w, p, b: d.edges(w)),
    ("POST", "/edges/{edge_id}/unlock", lambda d, w, p, b: d.phoned_unlock(w, p["edge_id"], b)),
    ("POST", "/edges/{edge_id}/incidents/{incident_id}/close", lambda d, w, p, b: d.close_incident(w, p["edge_id"], p["incident_id"], b)),
    ("GET", "/me/visit-leases", lambda d, w, p, b: d.my_visit_leases(w)),
    ("POST", "/me/visit-leases/{lease_id}/carried", lambda d, w, p, b: d.carried_lease(w, p["lease_id"])),
    ("POST", "/edges/{edge_id}/ceiling", lambda d, w, p, b: d.set_ceiling(w, p["edge_id"], b)),
    ("GET", "/edge-key", lambda d, w, p, b: d.edge_key()),                       # public, served before sign-in (below)
    # decision 0014: what an edge agent calls, signed with its enrolment key (KeyClerk-Edge header), never a session
    ("GET", "/edge/bundle", lambda d, w, p, b: d.edge_bundle(w["edge"], p.get("serial"), w.get("quote"), w.get("request"),
                                                            p.get("after"), p.get("wait"))),
    ("GET", "/edge/lease/{lease_id}/email", lambda d, w, p, b: d.edge_email(w["edge"], p["lease_id"], w.get("request"))),
    ("GET", "/edge/module/{sha256}", lambda d, w, p, b: d.edge_module(w["edge"], p["sha256"])),
    ("GET", "/edge/attest/challenge", lambda d, w, p, b: d.edge_attest_challenge(w["edge"])),
    ("POST", "/edge/attest/activate", lambda d, w, p, b: d.edge_attest_activate(w["edge"], b)),
    ("POST", "/edge/report", lambda d, w, p, b: d.edge_report(w["edge"], b)),
    ("POST", "/edge/relay", lambda d, w, p, b: d.edge_relay(w["edge"], b)),
    ("POST", "/edge/escrow", lambda d, w, p, b: d.edge_escrow(w["edge"], b)),
    ("POST", "/edge/incident", lambda d, w, p, b: d.edge_incident(w["edge"], b)),
    ("POST", "/edge/evidence", lambda d, w, p, b: d.edge_evidence(w["edge"], b)),
    ("GET", "/openapi.json", lambda d, w, p, b: contract()),     # served before sign-in (below); listed so the
]                                                                 # route table and the contract stay one set


@lru_cache(maxsize=1)
def contract() -> dict:
    return json.loads((Path(__file__).resolve().parent / "schema" / "api.openapi.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _request_validator():
    import jsonschema
    c = contract()
    return jsonschema.Draft202012Validator({"$ref": "#/components/schemas/ChangeRequest", "components": c["components"]})


def _qs(query: str, max_num_fields: int) -> dict:
    """A query string, bounded: too many fields is the caller's mistake (400), never a server error (found by fuzzing)."""
    try:
        return parse_qs(query, max_num_fields=max_num_fields)
    except ValueError:
        raise ApiError(400, "invalid", "too many query parameters") from None


def _match(method: str, path: str):
    for m, pattern, call in ROUTES:
        if m != method:
            continue
        rx = "^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$"
        hit = re.match(rx, path)
        if hit:
            return call, {k: unquote(v) for k, v in hit.groupdict().items()}
    return None, None


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, next_steps: list | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.next = status, code, message, next_steps or []


def handler(desk: Desk, auth, allowed_hosts: set[str], api_clients: tuple[str, ...], secure_cookie: bool,
            dpop_clients: tuple[str, ...] = (), readiness=None):
    gate = threading.BoundedSemaphore(MAX_CONCURRENT)
    inflight: dict[str, int] = {}
    inflight_lock = threading.Lock()
    from keyclerk import edge as _edge
    edge_replay = _edge.Replay()                 # nonces of signed edge requests (decision 0014)
    scans: dict[str, deque] = {}                 # public phone scans per address, the last minute
    scan_lock = threading.Lock()
    flags = "HttpOnly; SameSite=Lax; Path=/" + ("; Secure" if secure_cookie else "")

    class H(BaseHTTPRequestHandler):
        server_version = "keyclerk"
        sys_version = ""
        timeout = SOCKET_SECONDS

        def log_message(self, *a):
            pass

        def _send(self, status: int, body: bytes = b"", ctype: str = "application/json", extra: tuple = (),
                  cache: str = "no-store", csp: str | None = None):
            self.send_response(status)
            heads = HEADERS if csp is None else (("Content-Security-Policy", csp), *HEADERS[1:])
            for k, v in (("Content-Type", ctype), ("Content-Length", str(len(body))), ("Cache-Control", cache), *heads, *extra):
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj, separators=(",", ":")).encode())

        def _error(self, e: ApiError) -> None:
            err = {"code": e.code, "message": guard.safe_for_log(e.message, 300)}
            if e.next:
                err["next"] = e.next
            self._json(e.status, {"error": err})

        def _who(self, cookies: dict) -> tuple[dict, bool]:
            authz = self.headers.get("Authorization") or ""
            scheme = authz.split(" ", 1)[0]
            if scheme in ("Bearer", "DPoP"):
                if auth is None or not api_clients:
                    raise ApiError(401, "unauthenticated", "bearer tokens are not accepted here")
                token = authz[len(scheme):].strip()
                try:
                    who = auth.bearer(token, api_clients)
                except Exception:   # noqa: BLE001 - why a token failed is not echoed
                    raise ApiError(401, "unauthenticated", "the bearer token is not valid here") from None
                if scheme == "DPoP" or who.get("azp") in dpop_clients or who.get("cnf_jkt"):
                    if who.get("azp") in dpop_clients and scheme != "DPoP":
                        raise ApiError(401, "unauthenticated", "this client must send DPoP-bound tokens")
                    from keyclerk import dpop
                    origin = auth.redirect_uri.split("/", 3)
                    url = f"{origin[0]}//{origin[2]}{urlparse(self.path).path}"
                    try:
                        dpop.check(self.headers.get("DPoP") or "", self.command, url, token, who.get("cnf_jkt"))
                    except guard.InputRejected as e:
                        raise ApiError(401, "unauthenticated", f"proof of possession: {e}") from None
                return who, False
            if "Authorization" in self.headers:   # presented and not understood (even blank) ends here: never the cookie
                raise ApiError(401, "unauthenticated", "only Bearer or DPoP tokens are accepted in Authorization")
            who = auth.who(cookies.get(COOKIE)) if auth is not None else None
            if who is None:
                raise ApiError(401, "unauthenticated", "sign in at /login")
            return who, True

        def _route(self, method: str):
            try:
                raw = self._read_body() if method == "POST" else b""
            except ApiError as e:
                return self._error(e)
            except OSError:
                return                                       # the sender went away or stalled: nothing to answer
            if not gate.acquire(timeout=BUSY_WAIT_SECONDS):
                return self._error(ApiError(503, "busy", "busy, try again"))
            try:
                if len(self.path) > 2048:
                    raise ApiError(400, "invalid", "request line too long")
                if method == "GET" and self.path in ("/healthz", "/readyz"):   # decision 0018 H1: status only, any Host
                    if self.path == "/healthz":
                        return self._send(200, b"ok\n", "text/plain; charset=utf-8")
                    ok = readiness is None or readiness.ready()
                    return self._send(200 if ok else 503, b"ready\n" if ok else b"not ready\n", "text/plain; charset=utf-8")
                if (self.headers.get("Host") or "").lower() not in allowed_hosts:
                    raise ApiError(400, "invalid", "unknown host")
                u = urlparse(self.path)
                cookies = parse_cookies(self.headers.get("Cookie"))
                if method == "GET" and u.path in STATIC:
                    name, ctype = STATIC[u.path]
                    return self._send(200, (UI / name).read_bytes(), ctype, cache="no-cache")
                if method == "GET" and (u.path in ("/login", "/callback", "/logout") or u.path.startswith("/approve/")):
                    return self._auth_flow(u, cookies)
                if method == "GET" and u.path.startswith("/approve-qr/"):
                    return self._qr(u)
                if method == "GET" and u.path == "/api/v1/openapi.json":
                    return self._json(200, contract())
                if method == "GET" and (u.path.startswith("/api/v1/scan/") or u.path == "/api/v1/qr-key"):
                    return self._public_visit(u)
                if method == "GET" and u.path == "/api/v1/edge-key":
                    return self._json(200, desk.edge_key())
                if not u.path.startswith("/api/v1/"):
                    raise ApiError(404, "not_found", "no such page")
                call, params = _match(method, u.path[len("/api/v1"):])
                if call is not None:              # the query parameters the contract names: at (a moment), serial (a re-fetch)
                    q = _qs(u.query, max_num_fields=4)
                    if "at" in q:
                        params = {**params, "at": q["at"][0][:40]}
                    if "serial" in q:
                        params = {**params, "serial": q["serial"][0][:12]}
                    for k in ("after", "wait"):                  # decision 0026: the bundle long-poll
                        if k in q:
                            params = {**params, k: q[k][0][:12]}
                if call is None:
                    any_method = any(_match(m, u.path[len("/api/v1"):])[0] for m in ("GET", "POST"))
                    raise ApiError(405 if any_method else 404, "not_allowed" if any_method else "not_found", "no such call")
                if u.path.startswith("/api/v1/edge/"):       # an edge agent: its signature, never a session or a token
                    if "Authorization" in self.headers or COOKIE in cookies:
                        raise ApiError(401, "unauthenticated", "an edge signs with KeyClerk-Edge only")
                    try:
                        eid = _edge.check_request(self.headers.get("KeyClerk-Edge") or "", method, self.path, raw,
                                                  desk.edge_public_of, edge_replay)
                    except ValueError as e:
                        raise ApiError(401, "unauthenticated", str(e)) from None
                    hdr = (self.headers.get("KeyClerk-Edge") or "").split(";")
                    who, browser = {"edge": eid, "request": (hdr[1], hdr[2]),
                                    "quote": (self.headers.get("KeyClerk-Quote") or None)}, False
                    ended = desk.edge_ended(eid)
                    if ended is not None:                    # told once it is over: revocation, not an outage
                        return self._json(410, ended)
                else:
                    who, browser = self._who(cookies)
                person = str(who.get("sub") or who.get("anchor") or "edge:" + str(who.get("edge")))
                with inflight_lock:
                    if inflight.get(person, 0) >= PER_PERSON:
                        raise ApiError(429, "rate_limited", f"at most {PER_PERSON} requests at once per person")
                    inflight[person] = inflight.get(person, 0) + 1
                    self._person = person
                body = None
                if method == "POST":
                    if browser:
                        if self.headers.get("X-KeyClerk-CSRF") != who.get("csrf"):
                            raise ApiError(403, "csrf", "the X-KeyClerk-CSRF header is missing or wrong")
                        origin = self.headers.get("Origin")
                        if origin and urlparse(origin).netloc.lower() not in allowed_hosts:
                            raise ApiError(403, "csrf", "a request from another site")
                    body = self._body(u.path, raw)
                if (u.path.startswith("/api/v1/relay/") or u.path.endswith("/carried")) and not browser:
                    raise ApiError(403, "forbidden", "a relayed secret is handed over to a browser session only")
                result = call(desk, who, params, body)
                if u.path.endswith("/approval-sign-in"):        # a browser approval: the sign-in that signs (decision 0006)
                    if not browser or auth is None:
                        raise ApiError(403, "forbidden", "this starts an approval for a browser session on this desk; another "
                                       "front end signs in at the broker itself with the nonce from GET /statement")
                    url, flow = auth.login(nonce=result["nonce"], purpose={"approve": result["change_id"], "anchor": result["by"]})
                    return self._send(200, json.dumps({"redirect": url}).encode(), "application/json",
                                      (("Set-Cookie", f"{FLOW_COOKIE}={flow}; Max-Age=300; {flags}"),))
                if u.path == "/api/v1/me":
                    result = {**result, "csrf": who.get("csrf") if browser else None,
                              "approval_sign_in": desk.proofs_required(),
                              "account_url": (f"{auth.public_issuer}/account/#/account-security/signing-in"
                                              if getattr(auth, "public_issuer", None) else None)}
                self._json(200, result)
            except ApiError as e:
                self._error(e)
            except Throttled as e:
                self._error(ApiError(429, "rate_limited", str(e), [{"why": "You made many changes in a short time.",
                                                                     "do": "Wait a few minutes, then try again.", "who": []}]))
            except Refusal as e:
                self._error(ApiError(422, "refused", str(e), getattr(e, "next", [])))
            except SignerRefused as e:                        # the checking signer said no (decision 0015)
                self._error(ApiError(422, "refused", f"the signer refused to sign it: {e}",
                                     [{"why": "The records signer checks every change again before it is signed.",
                                       "do": "Tell the operator: the desk and the signer disagree.", "who": []}]))
            except guard.InputRejected as e:
                self._error(ApiError(400, "invalid", str(e)))
            except PermissionError as e:
                self._error(ApiError(403, "forbidden", str(e)))
            except LookupError as e:
                self._error(ApiError(404, "not_found", str(e)))
            except Exception as e:   # noqa: BLE001 - never a stack trace to the caller
                sys.stderr.write(f"keyclerk.api: {type(e).__name__}: {guard.safe_for_log(e, 300)}\n")
                self._error(ApiError(500, "internal", "internal error"))
            finally:
                person = getattr(self, "_person", None)
                if person is not None:
                    with inflight_lock:
                        inflight[person] -= 1
                        if not inflight[person]:
                            del inflight[person]
                    self._person = None
                gate.release()

        def _read_body(self) -> bytes:
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                raise ApiError(400, "invalid", "bad Content-Length") from None
            if n > MAX_BODY:
                raise ApiError(413, "too_large", f"a body is at most {MAX_BODY} bytes")
            raw = self.rfile.read(n) if n > 0 else b""
            if len(raw) < max(n, 0):
                raise OSError("the body ended early")
            return raw

        def _body(self, path: str, raw: bytes):
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if path in ("/api/v1/changes", "/api/v1/changes/preview"):
                if ctype != "application/json":
                    raise ApiError(415, "unsupported_media", "send application/json")
                body = guard.load_json_bytes(raw, "request", MAX_BODY)
                errs = sorted(_request_validator().iter_errors(body), key=lambda x: x.path)
                if errs:
                    raise ApiError(400, "invalid", "the request does not match the contract: " + errs[0].message[:200])
                return body
            if path.startswith("/api/v1/edge/") or re.fullmatch(r"/api/v1/edges/[^/]+/(ceiling|unlock|incidents/[^/]+/close)", path):
                if ctype != "application/json":
                    raise ApiError(415, "unsupported_media", "send application/json")
                return guard.load_json_bytes(raw, "request", MAX_BODY)
            if path.endswith("/approve") and raw.strip() not in (b"", b"{}"):
                if ctype != "application/json":
                    raise ApiError(415, "unsupported_media", "send application/json")
                body = guard.load_json_bytes(raw, "request", MAX_BODY)
                if not (isinstance(body, dict) and set(body) <= {"proof"} and isinstance(body.get("proof"), str)
                        and len(body["proof"]) <= 16384):
                    raise ApiError(400, "invalid", "an approval takes {\"proof\": \"<the broker's ID token>\"} or nothing")
                return body
            if raw.strip() not in (b"", b"{}"):
                raise ApiError(400, "invalid", "this call takes no body")
            return None

        def _auth_flow(self, u, cookies):
            if auth is None:
                raise ApiError(404, "not_found", "sign-in is not configured")
            if u.path == "/login":
                url, flow = auth.login(fresh=_qs(u.query, max_num_fields=2).get("fresh", [""])[0] == "1")
                return self._send(302, b"", "text/plain", (("Set-Cookie", f"{FLOW_COOKIE}={flow}; Max-Age=300; {flags}"),
                                                           ("Location", url)))
            if u.path.startswith("/approve/"):         # a phone link: first a page that says what is approved (#1)
                cid = unquote(u.path[len("/approve/"):])
                q = _qs(u.query, max_num_fields=5)
                anchor, exp, sig = (q.get(k, [""])[0] for k in ("for", "exp", "sig"))
                if not sig:
                    return self._send(404, b"Approving starts on the Approvals page of the desk.", "text/plain; charset=utf-8")
                if not desk.phone_link_valid(cid, anchor, exp, sig):
                    return self._send(400, b"This approval link is not valid or has expired: make a new one on the desk.",
                                      "text/plain; charset=utf-8")
                st = desk.statement({"anchor": anchor, "roles": []}, cid)
                return self._phone_page(cid, st, anchor, exp, sig)
            if u.path == "/logout":
                if (self.headers.get("Sec-Fetch-Site") or "same-origin") not in ("same-origin", "none"):
                    raise ApiError(403, "csrf", "sign out from this site")      # another site cannot sign you out
                return self._send(302, b"", "text/plain", (("Set-Cookie", f"{COOKIE}=; Max-Age=0; {flags}"),
                                                           ("Location", auth.logout_url())))
            q = _qs(u.query, max_num_fields=10)
            try:
                purpose, value = auth.complete(q.get("code", [""])[0], q.get("state", [""])[0], cookies.get(FLOW_COOKIE, ""))
            except Exception:   # noqa: BLE001 - never echo why a sign-in failed
                return self._send(400, b"Sign-in failed. Go back to / and try again.", "text/plain; charset=utf-8")
            if purpose:                                   # the approval's signature came back
                who = auth.who(cookies.get(COOKIE))
                clear = ("Set-Cookie", f"{FLOW_COOKIE}=; Max-Age=0; {flags}")
                if purpose.get("phone"):                  # on a phone: the token's own anchor is who approves
                    who = {"anchor": auth.anchor_of(value.get("claims") or {}), "sub": (value.get("claims") or {}).get("sub"),
                           "roles": []}
                if who is None or who.get("anchor") != purpose.get("anchor"):
                    return self._send(400, b"Approval not recorded: sign in as the person who approves.",
                                      "text/plain; charset=utf-8", (clear,))
                try:
                    r = desk.approve(who, purpose["approve"], value["id_token"])
                except (Refusal, guard.InputRejected, PermissionError) as e:
                    lines = [f"Approval not recorded: {guard.safe_for_log(e, 300)}.", ""]
                    for st in getattr(e, "next", [])[:5]:     # why, and what would complete it
                        who = ", ".join(w.get("name") or w.get("anchor") for w in st.get("who", []))
                        lines += [f"- {st['why']} {st['do']}" + (f" Who: {who}." if who else "")]
                    lines += ["", "Back to the desk: /#/changes"]
                    return self._send(422, "\n".join(lines).encode(), "text/plain; charset=utf-8", (clear,))
                if purpose.get("phone"):
                    words = {"applied": "Approved: the change is applied.",
                             "pending": "Approved: your key is added; the change waits for another key."}
                    return self._send(200, words.get(r["outcome"], "Recorded.").encode(), "text/plain; charset=utf-8", (clear,))
                return self._send(302, b"", "text/plain", (clear, ("Location", f"/#/changes/{r['outcome']}")))
            return self._send(302, b"", "text/plain", (("Set-Cookie", f"{COOKIE}={value}; {flags}"),
                                                       ("Set-Cookie", f"{FLOW_COOKIE}=; Max-Age=0; {flags}"), ("Location", "/")))

        def _phone_page(self, cid, st, anchor, exp, sig):
            import html
            e = lambda s: html.escape(str(s), quote=True)   # noqa: E731
            broker = auth.public_issuer.split("/realms/")[0]
            page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
                    f'content="width=device-width,initial-scale=1"><title>Approve</title><link rel="stylesheet" href="/app.css">'
                    f'</head><body><main><h1>Approve this change?</h1><div class="card"><p><b>{e(st["summary"])}</b></p>'
                    f'<p class="small muted">Records: {e(", ".join(st["records"]))}</p></div>'
                    f'<p>Your approval is your own signature: you sign in again, with your passkey, as the person this link '
                    f'was made for. Only continue if you meant to approve exactly this.</p>'
                    f'<form method="post" action="/approve/{e(cid)}"><input type="hidden" name="for" value="{e(anchor)}">'
                    f'<input type="hidden" name="exp" value="{e(exp)}"><input type="hidden" name="sig" value="{e(sig)}">'
                    f'<button type="submit">Sign in to approve</button></form></main></body></html>')
            csp = CSP.replace("form-action 'self'", f"form-action 'self' {broker}")
            return self._send(200, page.encode(), "text/html; charset=utf-8", csp=csp)

        def _phone_post(self):
            """The phone page's button: the signed link again, then the broker's sign-in with the statement as nonce."""
            cid = unquote(urlparse(self.path).path[len("/approve/"):])
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if auth is None or not 0 < n <= 4096:
                return self._send(400, b"Bad request.", "text/plain; charset=utf-8")
            q = _qs(self.rfile.read(n).decode("ascii", "replace"), max_num_fields=5)
            anchor, exp, sig = (q.get(k, [""])[0] for k in ("for", "exp", "sig"))
            if not desk.phone_link_valid(cid, anchor, exp, sig):
                return self._send(400, b"This approval link is not valid or has expired: make a new one on the desk.",
                                  "text/plain; charset=utf-8")
            try:
                st = desk.statement({"anchor": anchor, "roles": []}, cid)
            except Refusal as e:
                return self._send(422, f"Not possible: {e}.".encode(), "text/plain; charset=utf-8")
            url, flow = auth.login(nonce=st["nonce"], purpose={"approve": st["change_id"], "anchor": st["by"], "phone": True})
            return self._send(303, b"", "text/plain", (("Set-Cookie", f"{FLOW_COOKIE}={flow}; Max-Age=300; {flags}"),
                                                       ("Location", url)))

        def _qr(self, u):
            """The phone link as a QR code (an SVG image), for a valid, unexpired link only."""
            import io
            import segno
            cid = unquote(u.path[len("/approve-qr/"):])
            q = _qs(u.query, max_num_fields=5)
            anchor, exp, sig = (q.get(k, [""])[0] for k in ("for", "exp", "sig"))
            if not desk.phone_link_valid(cid, anchor, exp, sig):
                raise ApiError(404, "not_found", "no such approval link")
            buf = io.BytesIO()
            segno.make(f"{desk.public_base}/approve/{u.path[len('/approve-qr/'):]}?{u.query}", error="m").save(
                buf, kind="svg", scale=5, border=2, dark="#1F0E36", light="#ffffff", xmldecl=False)
            return self._send(200, buf.getvalue(), "image/svg+xml")

        def _public_visit(self, u):
            """The phone scan and the QR public key: no sign-in, a small budget per address (decision 0009, D2)."""
            from keyclerk import visits as V
            if u.path == "/api/v1/qr-key":
                return self._json(200, desk.qr_key())
            ip, now = self.client_address[0], time.monotonic()
            per = int(V.rules().get("scan_per_minute", 30))
            with scan_lock:
                q = scans.setdefault(ip, deque())
                while q and now - q[0] > 60:
                    q.popleft()
                if len(q) >= per or len(scans) > 10000:
                    raise ApiError(429, "rate_limited", "too many scans from here; wait a minute")
                q.append(now)
            token = unquote(u.path[len("/api/v1/scan/"):])
            if len(token) > 400:
                raise ApiError(400, "invalid", "that is not a visit code")
            return self._json(200, desk.scan(token))

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            if urlparse(self.path).path.startswith("/approve/"):
                if (self.headers.get("Host") or "").lower() not in allowed_hosts:
                    return self._error(ApiError(400, "invalid", "unknown host"))
                return self._phone_post()
            if urlparse(self.path).path == "/backchannel-logout":       # the broker ends sessions (no cookie, no CSRF)
                if (self.headers.get("Host") or "").lower() not in allowed_hosts:
                    return self._error(ApiError(400, "invalid", "unknown host"))
                from keyclerk.oidc import backchannel_post
                return self._send(backchannel_post(auth, self.headers, self.rfile), b"", "text/plain")
            self._route("POST")

        def _no(self):
            path = urlparse(self.path).path
            api = path[len("/api/v1"):] if path.startswith("/api/v1") else None
            allow = [m for m in ("GET", "POST") if api is not None and _match(m, api)[0] is not None] or ["GET"]
            body = json.dumps({"error": {"code": "not_allowed", "message": "not a KeyClerk call"}}, separators=(",", ":")).encode()
            self._send(405, body, extra=(("Allow", ", ".join(allow)),))     # RFC 9110: a 405 names what is allowed

        def send_error(self, code, message=None, explain=None):
            """Methods this server has no handler for (QUERY, anything new) come here as a 501: answer them as every
            other unsupported method, a JSON 405 with Allow (found by fuzzing)."""
            if code == 501:
                return self._no()
            body = json.dumps({"error": {"code": "invalid" if code < 500 else "internal",
                                         "message": guard.safe_for_log(message or "", 200)}}, separators=(",", ":")).encode()
            self._send(code, body)

        # every other method gets the desk's own JSON answer, never the HTTP server's HTML 501 (found by fuzzing)
        do_PUT = do_DELETE = do_PATCH = do_TRACE = do_OPTIONS = do_CONNECT = do_HEAD = _no

    return H


TIMER_SECONDS = 30


def _visit_timers(desk: Desk) -> None:
    """The visit timers' schedule (decision 0009): every half minute the desk asks visits.rego which steps are due."""
    while True:
        time.sleep(TIMER_SECONDS)
        try:
            desk.tick()
        except Exception as e:  # noqa: BLE001 - a failed tick is logged and retried; it never stops the desk
            print(f"visit timers: {guard.safe_for_log(e, 300)}", flush=True)


FOLLOW_SECONDS = 15


def _follow(store) -> None:
    """The desk on the change log (decision 0022 S5): what the signer learned since, every quarter minute; a failure is
    kept for readiness and keyclerk_log_breaks, and retried."""
    while True:
        time.sleep(FOLLOW_SECONDS)
        try:
            store.refresh()
        except Exception as e:  # noqa: BLE001 - kept by the store, logged, retried; the desk reads on
            print(f"following the signer: {guard.safe_for_log(e, 300)}", flush=True)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="keyclerk.api")
    ap.add_argument("--config", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--signing-key", help="the records key in this process (development); with --signer it stays in the signer")
    ap.add_argument("--signer", help="the checking signer: unix:/path or tcp:127.0.0.1:port (decision 0015)")
    ap.add_argument("--signer-token", help="the token file for a TCP signer")
    ap.add_argument("--seed")
    ap.add_argument("--broker-state")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8091)
    ap.add_argument("--allowed-host", action="append")
    ap.add_argument("--oidc-public-issuer", required=True)
    ap.add_argument("--oidc-internal-issuer")
    ap.add_argument("--oidc-client", default="keyclerk-desk")
    ap.add_argument("--oidc-redirect", required=True)
    ap.add_argument("--viewer-role", default="keyclerk-viewer")
    ap.add_argument("--api-client", action="append", default=[], help="a broker client whose bearer tokens are accepted")
    ap.add_argument("--dpop-client", action="append", default=[], help="an API client whose tokens must be DPoP-bound")
    ap.add_argument("--mgmt-host", default="127.0.0.1", help="the management listener (metrics, readiness detail)")
    ap.add_argument("--mgmt-port", type=int, help="off unless given (decision 0018)")
    ap.add_argument("--mgmt-token-file", help="the management listener's bearer token, at least 32 characters")
    a = ap.parse_args(argv)
    if not 1 <= a.port <= 65535:
        ap.error("bad port")
    if a.mgmt_port is not None and (not 1 <= a.mgmt_port <= 65535 or a.mgmt_port == a.port or not a.mgmt_token_file):
        ap.error("--mgmt-port needs its own port and --mgmt-token-file")
    for c in a.api_client:
        guard.name(c, "api client")
    config.configure(a.config)
    from keyclerk.oidc import Oidc
    auth = Oidc(public_issuer=a.oidc_public_issuer.rstrip("/"),
                internal_issuer=(a.oidc_internal_issuer or a.oidc_public_issuer).rstrip("/"),
                client_id=a.oidc_client, redirect_uri=a.oidc_redirect, viewer_role=a.viewer_role)
    from keyclerk.approvals import BrokerProofs
    policy = config.current().get("approvals") or {}
    proofs = BrokerProofs({auth.public_issuer, auth.internal_issuer}, {auth.client_id, *a.api_client},
                          policy.get("max_age_seconds", 300), f"{auth.internal_issuer}/protocol/openid-connect/certs",
                          Path(a.store) / "broker-keys.json", acr=policy.get("acr"))
    auth.approval_acr = policy.get("acr")
    base = "/".join(a.oidc_redirect.split("/", 3)[:3])
    if not (a.signer or a.signing_key):
        ap.error("--signer (a checking signer) or --signing-key (the key in this process)")
    signer = None
    if a.signer:
        from keyclerk.signer import SignerClient
        signer = SignerClient(a.signer, a.signer_token)
    from keyclerk.store.desk_store import StoreChoiceRefused, open_desk_store
    try:
        store = open_desk_store(config.current(), Path(a.store),
                                Path(a.signing_key) if a.signing_key and not signer else None,
                                Path(a.seed) if a.seed else None, signer=signer)
    except (StoreChoiceRefused, ValueError) as e:
        raise SystemExit(f"keyclerk desk: {e}") from None
    if hasattr(store, "follower"):                # decision 0028: sign-in and proofs resolve through the mapping
        from keyclerk import anchors
        auth.resolve = lambda claims: anchors.resolve(store.store, claims)
        proofs.resolve = lambda claims: anchors.resolve(store.store, claims)
    desk = Desk(store,
                Path(a.broker_state) if a.broker_state else None, proofs=proofs, public_base=base)
    hosts = {h.lower() for h in (a.allowed_host or [f"127.0.0.1:{a.port}", f"localhost:{a.port}"])}
    print(f"KeyClerk desk and API on {a.host}:{a.port}", flush=True)
    for c in a.dpop_client:
        guard.name(c, "dpop client")
    threading.Thread(target=_visit_timers, args=(desk,), name="visit-timers", daemon=True).start()
    if hasattr(store, "refresh"):
        threading.Thread(target=_follow, args=(store,), name="follow-signer", daemon=True).start()
    from keyclerk import health
    readiness = health.Readiness(desk, signer)
    health.register_gauges(desk, readiness)
    if a.mgmt_port is not None:
        mgmt = health.management_server((a.mgmt_host, a.mgmt_port), readiness, health.read_token(a.mgmt_token_file))
        threading.Thread(target=mgmt.serve_forever, name="management", daemon=True).start()
        print(f"KeyClerk management (metrics, readiness) on {a.mgmt_host}:{a.mgmt_port}", flush=True)
    Server((a.host, a.port), handler(desk, auth, hosts, tuple(a.api_client), a.oidc_redirect.startswith("https://"),
                                     tuple(a.dpop_client), readiness)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
