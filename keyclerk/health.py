# SPDX-License-Identifier: EUPL-1.2
"""Health, readiness and the management listener (decision 0018 H1, H2).

On the desk's own listener, before the host check (an orchestrator probes by address): `/healthz` answers "ok" while
the process serves, `/readyz` answers "ready" (200) or "not ready" (503) and nothing else. Ready means: the store opens
and its change log verifies, the policy modules load, the checking signer answers, and the reconciler's last run is
within `reconcile.ready_max_age_seconds`. Never a downstream system: a broker that is down is a metric and an alert,
not a reason to take the desk out of service. A restore in progress (decision 0019) joins the list when restores exist.

The answer is computed at most every READY_TTL seconds, whatever the probe rate, so probes cannot load the desk.

The management listener (off unless --mgmt-port is given) is for an operator and the monitoring stack, behind its
own bearer token: `/metrics` (keyclerk.metrics), `/readyz` with the reason of each check, `/healthz`."""
from __future__ import annotations

import hmac
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from keyclerk import guard, metrics

READY_TTL = 5.0
DEFAULT_RECONCILE_MAX_AGE = 900


class Readiness:
    """The readiness checks of one desk. `detail()` gives each check with its reason; `ready()` only the verdict."""

    def __init__(self, desk, signer=None, max_age: int | None = None, clock=time.monotonic):
        self.desk, self.signer, self.clock = desk, signer, clock
        self.max_age = max_age
        self._lock = threading.Lock()
        self._at = None
        self._last: dict = {}

    def _bound(self) -> int:
        if self.max_age is not None:
            return self.max_age
        from keyclerk import config
        return int((config.current().get("reconcile") or {}).get("ready_max_age_seconds", DEFAULT_RECONCILE_MAX_AGE))

    def _checks(self) -> dict:
        from keyclerk import restore
        out = {}
        path = getattr(self.desk.store, "path", None)
        if path is not None:                             # a store kept in a folder can be in restore mode (0019)
            restoring = restore.marker(path) is not None
            out["restore"] = (not restoring, "in restore mode: no writes, edges wait (python -m keyclerk.restore status)"
                              if restoring else "serving")
        try:
            self.desk.store.load()
            breaks = self.desk.store.verify_log()
            out["store"] = (not breaks, "the records open and the change log verifies" if not breaks
                            else f"{len(breaks)} breaks in the change log")
        except Exception as e:   # noqa: BLE001 - not ready, with the reason on the management listener only
            out["store"] = (False, f"the store does not open: {type(e).__name__}")
        try:
            from keyclerk import policy_wasm
            names = sorted(p.stem for p in policy_wasm.POLICY.glob("*.wasm"))
            for n in names:
                policy_wasm.load(n)
            out["policy"] = (bool(names), f"{len(names)} policy modules loaded")
        except Exception as e:   # noqa: BLE001
            out["policy"] = (False, f"a policy module does not load: {type(e).__name__}")
        if self.signer is not None:
            try:
                self.signer.ping()
                out["signer"] = (True, "the checking signer answers")
            except Exception as e:   # noqa: BLE001
                from keyclerk.signer import SignerRefused
                out["signer"] = (False, f"the checking signer is not ready: {e}" if isinstance(e, SignerRefused)
                                 else f"the checking signer does not answer: {type(e).__name__}")
        store = self.desk.store
        if hasattr(store, "follow_breaks"):           # the desk on the change log (decision 0022 S5)
            failure = getattr(store, "follow_failure", None)
            frozen = getattr(store, "frozen", None)
            out["log"] = (failure is None,
                          f"the desk cannot follow the checking signer: {failure}" if failure
                          else f"signing is frozen, the desk is read-only: {frozen}" if frozen
                          else "the desk follows the checking signer")
        w = getattr(store, "witness", None)
        if w:                                         # the signer's witnesses (decision 0022 point 5)
            errors = "; ".join(f"{n}: {c['error']}" for n, c in sorted(w["cosigners"].items()) if c.get("error"))
            out["witness"] = (not w["incident"],
                              f"the change log is unwitnessed since {w['unwitnessed_since']}"
                              + (", and signing is blocked" if w["blocking"] else "") + (f" ({errors})" if errors else "")
                              if w["incident"] else f"the witnesses hold {w['size']} links")
        age = reconcile_age(self.desk)
        if age is not None:
            bound = self._bound()
            out["reconcile"] = (age <= bound, "the reconciler has not run yet" if age == float("inf")
                                else f"the last reconcile started {int(age)} s ago (bound {bound} s)")
        return out

    def detail(self) -> dict:
        with self._lock:
            now = self.clock()
            if self._at is None or now - self._at >= READY_TTL:
                self._last = self._checks()
                self._at = now
            checks = dict(self._last)
        return {"ready": all(ok for ok, _ in checks.values()),
                "checks": {k: {"ok": ok, "why": why} for k, (ok, why) in sorted(checks.items())}}

    def ready(self) -> bool:
        return self.detail()["ready"]


def _last_run(desk) -> dict | None:
    f = (desk.broker_state / "runs.jsonl") if getattr(desk, "broker_state", None) else None
    if f is None or not f.exists():
        return None
    for line in reversed(guard.read_bounded(f).splitlines()[-5:]):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("at"):
            return r
    return None


def reconcile_age(desk) -> float | None:
    """Seconds since the reconciler's last run started; None when this desk has no reconciler state to read."""
    r = _last_run(desk)
    if r is None:
        return None if not getattr(desk, "broker_state", None) else float("inf")
    at = datetime.fromisoformat(str(r["at"]))
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - at).total_seconds())


def _backup_gauges() -> None:
    """Backup state as gauges when the configuration names where the manifests and the drill report are (0019)."""
    from keyclerk import backup, config
    b = (config.current() or {}).get("backup") or {}
    if b.get("manifests"):
        metrics.gauge_fn("keyclerk_backup_age_seconds",
                         lambda: backup.newest_age(Path(b["manifests"]), b.get("manifest_keys") or []))
    if b.get("manifests"):
        pins = b.get("manifest_keys") or []

        def due(kind):
            return float(sum(1 for f in backup.hygiene(Path(b["manifests"]), pins)["findings"] if f["kind"] == kind))
        metrics.gauge_fn("keyclerk_backup_escrow_unproven", lambda: due("escrow_unproven"))
        metrics.gauge_fn("keyclerk_backup_recipients_due_rotation", lambda: due("rotate"))
    if b.get("drill_report"):
        metrics.gauge_fn("keyclerk_backup_drill_failed",
                         lambda: 0.0 if backup.last_drill(Path(b["drill_report"]))["ok"] else 1.0)
        metrics.gauge_fn("keyclerk_backup_recovery_seconds",
                         lambda: float(backup.last_drill(Path(b["drill_report"]))["recovery_seconds"]))


def register_gauges(desk, readiness: Readiness) -> None:
    """The scrape-time gauges of one desk (keyclerk.metrics.SPEC)."""
    from keyclerk import __version__
    metrics.gauge_fn("keyclerk_build_info", lambda: [({"version": __version__}, 1.0)])
    metrics.gauge_fn("keyclerk_pending_changes", lambda: len(desk.store.pending()))
    metrics.gauge_fn("keyclerk_log_breaks", lambda: len(desk.store.verify_log())
                     + (desk.store.follow_breaks() if hasattr(desk.store, "follow_breaks") else 0))
    metrics.gauge_fn("keyclerk_signing_frozen", lambda: 1.0 if getattr(desk.store, "frozen", None) else 0.0)

    def unwitnessed():
        w = getattr(desk.store, "witness", None)
        if not w:
            raise LookupError("no witness configured")
        if not w["unwitnessed_since"]:
            return 0.0
        since = datetime.strptime(w["unwitnessed_since"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - since).total_seconds())
    metrics.gauge_fn("keyclerk_unwitnessed_seconds", unwitnessed)
    metrics.gauge_fn("keyclerk_ready", lambda: 1.0 if readiness.ready() else 0.0)

    def age():
        a = reconcile_age(desk)
        if a is None:
            raise LookupError("no reconciler state")
        return a
    metrics.gauge_fn("keyclerk_reconcile_age_seconds", age)
    _backup_gauges()

    def drift():
        r = _last_run(desk)
        if r is None:
            raise LookupError("no reconciler run")
        return len(r.get("findings") or [])
    metrics.gauge_fn("keyclerk_reconcile_drift", drift)

    def failed():
        r = _last_run(desk)
        if r is None:
            raise LookupError("no reconciler run")
        return 1.0 if (r.get("error") or r.get("refused")) else 0.0
    metrics.gauge_fn("keyclerk_reconcile_failed", failed)

    def silent():
        doc = desk.store.load()
        return sum(1 for e in doc.get("edges", []) if desk.edge_store.state(e["edge_id"]).get("silent"))
    metrics.gauge_fn("keyclerk_edges_silent", silent)


def management_server(address: tuple[str, int], readiness: Readiness, token: str, audit=None) -> ThreadingHTTPServer:
    """The operator's listener: every path behind the bearer token, GET only, no other state than the metrics.
    audit: (keyclerk.siem.Feed, the SIEM reader's token) serves GET /audit/events behind that token alone (issue 29):
    the reader sees the audit events and nothing else, and the management token does not read them."""
    if len(token) < 32 or (audit and len(audit[1]) < 32):
        raise ValueError("the management and SIEM reader tokens must be at least 32 characters")
    if audit and hmac.compare_digest(audit[1].encode(), token.encode()):
        raise ValueError("the SIEM reader's token is its own, never the management token")

    class H(BaseHTTPRequestHandler):
        server_version = "keyclerk"
        sys_version = ""
        timeout = 10

        def log_message(self, *a):
            pass

        def _send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
            self.send_response(status)
            for k, v in (("Content-Type", ctype), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"),
                         ("X-Content-Type-Options", "nosniff")):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            authz = self.headers.get("Authorization") or ""
            given = authz[7:].strip().encode() if authz.startswith("Bearer ") else b""
            path, _, query = self.path.partition("?")
            if path == "/audit/events":
                if not (audit and given and hmac.compare_digest(given, audit[1].encode())):
                    return self._send(401, b"unauthenticated\n")
                status, body = audit[0].answer(query)
                return self._send(status, json.dumps(body, sort_keys=True).encode(), "application/json")
            if not (given and hmac.compare_digest(given, token.encode())):
                return self._send(401, b"unauthenticated\n")
            if path == "/metrics":
                return self._send(200, metrics.render().encode(), "text/plain; version=0.0.4; charset=utf-8")
            if path == "/readyz":
                d = readiness.detail()
                return self._send(200 if d["ready"] else 503, json.dumps(d, indent=1).encode(), "application/json")
            if path == "/healthz":
                return self._send(200, b"ok\n")
            return self._send(404, b"not found\n")

        def do_POST(self):
            self._send(405, b"read only\n")

        do_PUT = do_DELETE = do_PATCH = do_POST

    from keyclerk.httpserve import DualStackHTTPServer
    return DualStackHTTPServer(address, H)


def read_token(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()
