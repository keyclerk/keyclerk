# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk console: a read-only view of the records, the plan and what the reconciler did.

It answers who holds what and why, who manages which group, what the situation levels are, and what the next
reconciliation would change. It writes nothing: every change goes through the records (a merge request) and the
reconciler, so the console needs no credential to the broker. Standard library only; binds to localhost by default.

    python -m keyclerk.console --config keyclerk.yaml --records records.yaml --state /var/lib/keyclerk [--port 8090]
"""
from __future__ import annotations

import argparse
import html
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from keyclerk import config, delegation as D, guard, records, situation as S
from keyclerk.httpserve import BUSY_WAIT_SECONDS, SOCKET_SECONDS, Server
from keyclerk.reconcile import desired

CSS = """
:root{--ink:#1F0E36;--plum:#5B2A6E;--paper:#FBF8F3;--line:#E6DFD3;--key:#E8762C;--ok:#2E7D5B;--warn:#B7791F;--bad:#B23A48;--muted:#6B6475}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:var(--ink);color:#fff;padding:14px 24px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header .mark{width:26px;height:26px;border-radius:6px;background:var(--key);display:grid;place-items:center;color:var(--ink);font-weight:800}
header h1{font-size:18px;margin:0;font-weight:700}header .realm{opacity:.75;font-size:13px}
nav{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto}nav a{color:#fff;text-decoration:none;padding:6px 10px;border-radius:6px;font-size:14px}
nav a.on,nav a:hover{background:var(--plum)}main{max-width:1180px;margin:0 auto;padding:20px 16px 60px}
h2{font-size:17px;margin:24px 0 10px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px}.card b{display:block;font-size:26px}
.card span{color:var(--muted);font-size:13px}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}th{background:#F3EEE6;font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);margin:1px 2px 1px 0;background:#fff}
.ok{color:var(--ok);border-color:var(--ok)}.warn{color:var(--warn);border-color:var(--warn)}.bad{color:var(--bad);border-color:var(--bad)}
.muted{color:var(--muted)}code{font-size:13px}.note{background:#fff;border-left:4px solid var(--key);padding:10px 14px;margin:12px 0;border-radius:6px}
.wrap{overflow-x:auto}
"""

PAGES = [("/", "Overview"), ("/people", "People"), ("/groups", "Groups"), ("/delegations", "Delegations"),
         ("/situation", "Situation"), ("/runs", "Runs")]


def e(x) -> str:
    return html.escape(str(x))


def pill(text: str, cls: str = "") -> str:
    return f'<span class="pill {cls}">{e(text)}</span>'


class Console:
    def __init__(self, records_path: Path, state: Path):
        self.records_path, self.state = records_path, state

    def load(self):
        """The records, the plan and the reconciler's state, through the guard; recomputed only when a file changed
        or a minute passed, so a burst of requests costs one computation."""
        stamps = tuple(f.stat().st_mtime if f.exists() else 0 for f in
                       (self.records_path, self.state / "observed.json", self.state / "runs.jsonl"))
        now = datetime.now(timezone.utc)
        cached = getattr(self, "_cache", None)
        if cached and cached[0] == stamps and (now - cached[1][1]).total_seconds() < 60:
            return cached[1]
        doc = records.load(self.records_path)
        want = desired(doc, now)
        obs_file = self.state / "observed.json"
        have = set()
        if obs_file.exists():
            obs = guard.load_json_bytes(obs_file.read_bytes(), "observed state", guard.MAX_FILE_BYTES)
            have = {(guard.text(g, "group", 300), guard.text(a, "anchor", 300)) for g, a in obs}
        runs = []
        if (self.state / "runs.jsonl").exists():
            lines = guard.read_bounded(self.state / "runs.jsonl").splitlines()[-500:]
            runs = [r for r in (guard.load_json_bytes(x.encode(), "run") for x in lines if x) if isinstance(r, dict)]
        result = (doc, now, want, have, runs)
        self._cache = (stamps, result)
        return result

    # --- pages ---------------------------------------------------------------------------------------------------

    def overview(self, q) -> str:
        doc, now, want, have, runs = self.load()
        last = runs[-1] if runs else None
        adds, removes = sorted(want - have), sorted(have - want)
        cards = [("people", len({a for p in doc.get("persons", []) for a in p["anchors"]})), ("grants", len(doc.get("grants", []))),
                 ("leases", len(doc.get("leases", []))), ("groups", len(doc.get("groups", []))),
                 ("delegations", len(doc.get("delegations", []))), ("memberships in the broker", len(have))]
        out = '<div class="cards">' + "".join(f'<div class="card"><b>{n}</b><span>{e(k)}</span></div>' for k, n in cards) + "</div>"
        if last:
            state = pill("error", "bad") if last.get("error") else pill("in sync", "ok") if not adds and not removes else pill("drift", "warn")
            out += (f'<div class="note">Last reconciliation {e(last["at"][:19].replace("T", " "))} UTC {state} '
                    f'&middot; {len(last.get("add", []))} added, {len(last.get("remove", []))} removed in {e(last.get("seconds"))} s</div>')
        else:
            out += '<div class="note">The reconciler has not run yet.</div>'
        out += "<h2>What the next reconciliation would change</h2>"
        if not adds and not removes:
            out += '<p class="muted">Nothing: the broker holds exactly what the records require now.</p>'
        else:
            rows = [(pill("remove", "bad"), g, a) for g, a in removes] + [(pill("add", "ok"), g, a) for g, a in adds]
            out += self.table(["", "group", "person"], [(r[0], e(r[1]), e(r[2])) for r in rows], raw=True)
        return out

    def people(self, q) -> str:
        doc, now, want, have, runs = self.load()
        names = {a: p["person"] for p in doc.get("persons", []) for a in p["anchors"]}
        kinds = {a: p["kind"] for p in doc.get("persons", []) for a in p["anchors"]}
        anchors = sorted({a for _, a in want | have} | set(names))
        rows = []
        for a in anchors:
            groups = sorted({g for g, x in want | have if x == a})
            cells = []
            for g in groups:
                cls = "ok" if (g, a) in want and (g, a) in have else "warn" if (g, a) in want else "bad"
                cells.append(f'<a href="/explain?anchor={e(a)}&group={e(g)}" style="text-decoration:none">{pill(g.split("/", 2)[-1], cls)}</a>')
            rows.append((e(names.get(a, "")), f"<code>{e(a)}</code>", e(kinds.get(a, "")), " ".join(cells) or '<span class="muted">none</span>'))
        legend = f'<p class="muted">{pill("in the broker", "ok")} {pill("pending add", "warn")} {pill("pending removal", "bad")} Click a group for why.</p>'
        return legend + self.table(["person", "anchor", "kind", "groups"], rows, raw=True)

    def groups(self, q) -> str:
        doc, now, want, have, runs = self.load()
        rows = []
        managers = {}
        for d in doc.get("delegations", []):
            if D.chain_status(doc, d["delegation_id"], now)[0] == "ok":
                for g in doc.get("groups", []):
                    if D.covers(doc, d["group"], g["group_id"]) and D.place_covers(doc, d, g["group_id"]):
                        managers.setdefault(g["group_id"], []).append(d["delegate"])
        for g in sorted(doc.get("groups", []), key=lambda x: (len(D.ancestors(doc, x["group_id"])), x["group_id"])):
            gid = g["group_id"]
            depth = len(D.ancestors(doc, gid)) - 1
            members = D.effective_members(doc, gid, now)
            risk = D.effective_risk(doc, gid)
            cls = {"low": "ok", "elevated": "warn", "privileged": "bad"}[risk]
            rows.append((f'{"&nbsp;" * 4 * depth}<b>{e(gid)}</b>', pill(risk, cls),
                         " ".join(pill(c["entitlement"]) for c in g.get("carries", [])),
                         e(len(members)), " ".join(pill(m) for m in sorted(set(managers.get(gid, [])))) or '<span class="muted">root only</span>'))
        return self.table(["group (tree)", "class", "carries", "members", "managed by"], rows, raw=True)

    def delegations(self, q) -> str:
        doc, now, want, have, runs = self.load()
        rows = []
        for d in doc.get("delegations", []):
            st, until = D.chain_status(doc, d["delegation_id"], now)
            cls = {"ok": "ok", "grace": "warn", "dead": "bad"}[st]
            chain = " &larr; ".join(e(x["delegation_id"]) for x in D.chain(doc, d["delegation_id"])) + " &larr; root"
            rows.append((e(d["delegation_id"]), e(d["delegate"]), e(d["group"]), " ".join(pill(p) for p in d["powers"]),
                         e(d["max_risk"]), pill(st + (f" until {str(until)[:10]}" if until else ""), cls), chain))
        return self.table(["delegation", "deputy", "subtree", "powers", "max class", "state", "chain"], rows, raw=True)

    def situation(self, q) -> str:
        doc, now, want, have, runs = self.load()
        if not doc.get("situations"):
            return '<p class="muted">No situation announcements in the records.</p>'
        rows = []
        for scope, lv in S.opa_data(doc, now).items():
            cls = {"normal": "ok", "elevated": "warn", "high": "bad", "severe": "bad"}
            rows.append((e(scope), pill(lv["restriction"], cls[lv["restriction"]]), pill(lv["activation"], cls[lv["activation"]])))
        due = S.reviews_due(doc, now)
        out = self.table(["scope", "restriction level", "activation level"], rows, raw=True)
        if due:
            out += "<h2>Reviews due</h2>" + self.table(["item", "what", "due"], [(e(x["item"]), e(x["what"]), e(x["due"])) for x in due], raw=True)
        return out

    def runs(self, q) -> str:
        *_, runs = self.load()
        def result(r):
            if r.get("error"):
                return pill("error", "bad")
            if r.get("refused"):
                return pill("refused", "bad")
            return pill("applied" if r.get("applied") else "dry run", "ok" if r.get("applied") else "warn")
        rows = [(e(str(r.get("at", ""))[:19].replace("T", " ")), result(r), e(len(r.get("add", []))), e(len(r.get("remove", []))),
                 e(r.get("seconds", "")), e(r.get("refused") or r.get("error") or r.get("alert") or ""))
                for r in reversed(runs[-50:])]
        return self.table(["at (UTC)", "result", "added", "removed", "seconds", "error"], rows, raw=True)

    def explain(self, q) -> str:
        doc, now, *_ = self.load()
        try:
            anchor = guard.ident(q.get("anchor", [""])[0], "anchor")
            group = guard.ident(q.get("group", [""])[0].lstrip("/"), "group")
            group = "/" + group
        except guard.InputRejected:
            return '<p class="muted">Not a valid person and group.</p>'
        gid = group.split("/", 2)[-1] if group.startswith("/groups/") else None
        out = f"<h2>Why <code>{e(anchor)}</code> is in <code>{e(group)}</code></h2>"
        if gid:
            paths = D.explain(doc, anchor, gid, now)
            out += "".join(f'<div class="note">{" &rarr; ".join(e(x) for x in p)}</div>' for p in paths) or \
                '<p class="muted">Not through a delegated group now (a pending removal).</p>'
        else:
            hits = [g for g in doc.get("grants", []) if g["subject"]["anchor"] == anchor] + \
                   [ls for ls in doc.get("leases", []) if ls["anchor"] == anchor]
            out += self.table(["record", "until"], [(e(h.get("grant_id") or h.get("lease_id")), e(h.get("end"))) for h in hits], raw=True)
        return out

    @staticmethod
    def table(head, rows, raw=False) -> str:
        return ('<div class="wrap"><table><tr>' + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" +
                "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table></div>")

    def page(self, path: str, q) -> tuple[int, str]:
        route = {"/": self.overview, "/people": self.people, "/groups": self.groups, "/delegations": self.delegations,
                 "/situation": self.situation, "/runs": self.runs, "/explain": self.explain}.get(path)
        if route is None:
            return 404, "<p>Not found.</p>"
        try:
            body = route(q)
        except Exception as ex:   # show the error, never a stack with data
            body = f'<div class="note">This view could not be built: {e(type(ex).__name__)}</div>'
        realm = ""
        try:
            realm = self.load()[0].get("realm", "")      # cached: one read per request
        except Exception:   # noqa: BLE001
            pass
        nav = "".join(f'<a href="{u}" class="{"on" if u == path else ""}">{e(t)}</a>' for u, t in PAGES)
        title = dict(PAGES).get(path, "Explain")
        return 200, (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                     f'<title>KeyClerk console</title><style>{CSS}</style></head><body><header><div class="mark">K</div><h1>KeyClerk</h1>'
                     f'<span class="realm">{e(realm)} &middot; read only</span><nav>{nav}</nav></header><main><h2>{e(title)}</h2>{body}</main></body></html>')


HEADERS = (("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
                                       "frame-ancestors 'none'"),
           ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store"),
           ("X-Frame-Options", "DENY"), ("Cross-Origin-Opener-Policy", "same-origin"),
           ("Cross-Origin-Resource-Policy", "same-origin"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
MAX_CONCURRENT = 16
COOKIE = "keyclerk_session"
FLOW_COOKIE = "keyclerk_flow"


def parse_cookies(header: str | None) -> dict:
    """Cookies from a header, bounded; a malformed pair is skipped, never an error."""
    out = {}
    for part in (header or "")[:8192].split(";")[:50]:
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out.setdefault(k, v)
    return out


def handler(console: Console, auth, allowed_hosts: set[str], secure_cookie: bool):
    """The request handler: GET only, Host allowlisted (no DNS rebinding), signed-in viewers only, bounded concurrency,
    every response with the same strict headers."""
    import threading
    gate = threading.BoundedSemaphore(MAX_CONCURRENT)

    class H(BaseHTTPRequestHandler):
        timeout = SOCKET_SECONDS
        server_version = "keyclerk"
        sys_version = ""

        def log_message(self, *a):
            pass

        def _send(self, code: int, body: str = "", extra: tuple = ()):
            raw = body.encode()
            self.send_response(code)
            for k, v in (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(raw))), *HEADERS, *extra):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _refuse(self, code: int, why: str):
            self._send(code, f"<p>{e(why)}</p>")

        def do_GET(self):
            if not gate.acquire(timeout=BUSY_WAIT_SECONDS):
                return self._refuse(503, "Busy, try again.")
            try:
                if len(self.path) > 2048:
                    return self._refuse(414, "Request too long.")
                host = (self.headers.get("Host") or "").lower()
                if host not in allowed_hosts:
                    return self._refuse(400, "Unknown host.")
                u = urlparse(self.path)
                q = parse_qs(u.query, max_num_fields=10)
                if auth is not None:
                    flags = "HttpOnly; SameSite=Lax; Path=/" + ("; Secure" if secure_cookie else "")
                    cookies = parse_cookies(self.headers.get("Cookie"))
                    if u.path == "/login":
                        url, flow = auth.login()
                        return self._send(302, "", (("Set-Cookie", f"{FLOW_COOKIE}={flow}; Max-Age=300; {flags}"),
                                                    ("Location", url)))
                    if u.path == "/callback":
                        try:
                            value = auth.callback(q.get("code", [""])[0], q.get("state", [""])[0],
                                                  cookies.get(FLOW_COOKIE, ""))
                        except Exception:   # noqa: BLE001 - never echo why a sign-in failed in detail
                            return self._refuse(400, "Sign-in failed.")
                        return self._send(302, "", (("Set-Cookie", f"{COOKIE}={value}; {flags}"),
                                                    ("Set-Cookie", f"{FLOW_COOKIE}=; Max-Age=0; {flags}"), ("Location", "/")))
                    who = auth.who(cookies.get(COOKIE))
                    if who is None:
                        return self._send(302, "", (("Location", "/login"),))
                    if auth.viewer_role not in who.get("roles", []):
                        return self._refuse(403, "You are not a KeyClerk viewer.")
                code, text = console.page(u.path, q)
                self._send(code, text)
            finally:
                gate.release()

        def _no(self):
            self._refuse(405, "Read only.")

        def do_POST(self):
            if urlparse(self.path).path != "/backchannel-logout" or \
                    (self.headers.get("Host") or "").lower() not in allowed_hosts:
                return self._no()
            from keyclerk.oidc import backchannel_post
            self._send(backchannel_post(auth, self.headers, self.rfile))       # the broker ends sessions

        do_PUT = do_DELETE = do_PATCH = _no

    return H


def serve(console: Console, host: str, port: int, auth=None, allowed_hosts: set[str] | None = None,
          secure_cookie: bool = False):
    hosts = allowed_hosts or {f"127.0.0.1:{port}", f"localhost:{port}"}
    Server((host, port), handler(console, auth, hosts, secure_cookie)).serve_forever()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="keyclerk.console")
    ap.add_argument("--config", required=True)
    ap.add_argument("--records", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--allowed-host", action="append", help="Host header values accepted (default 127.0.0.1:PORT, localhost:PORT)")
    ap.add_argument("--oidc-public-issuer", help="the broker realm as the browser reaches it")
    ap.add_argument("--oidc-internal-issuer", help="the broker realm as this server reaches it")
    ap.add_argument("--oidc-client", default="keyclerk-console")
    ap.add_argument("--oidc-redirect", help="this console's /callback URL as the browser reaches it")
    ap.add_argument("--viewer-role", default="keyclerk-viewer")
    ap.add_argument("--insecure-no-auth", action="store_true", help="only with --host 127.0.0.1: no sign-in (a local demo)")
    a = ap.parse_args(argv)
    if not 1 <= a.port <= 65535:
        ap.error("bad port")
    config.configure(a.config)
    auth = None
    if a.insecure_no_auth:
        if a.host != "127.0.0.1":
            ap.error("--insecure-no-auth only when bound to 127.0.0.1")
    else:
        if not (a.oidc_public_issuer and a.oidc_redirect):
            ap.error("sign-in needs --oidc-public-issuer and --oidc-redirect (or --insecure-no-auth on 127.0.0.1)")
        from keyclerk.oidc import Oidc
        auth = Oidc(public_issuer=a.oidc_public_issuer.rstrip("/"),
                    internal_issuer=(a.oidc_internal_issuer or a.oidc_public_issuer).rstrip("/"),
                    client_id=a.oidc_client, redirect_uri=a.oidc_redirect, viewer_role=a.viewer_role)
    hosts = {h.lower() for h in (a.allowed_host or [])} or None
    print(f"KeyClerk console on {a.host}:{a.port} (read only, {'sign-in required' if auth else 'NO sign-in: local demo'})", flush=True)
    serve(Console(Path(a.records), Path(a.state)), a.host, a.port, auth, hosts,
          secure_cookie=bool(a.oidc_redirect and a.oidc_redirect.startswith("https://")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
