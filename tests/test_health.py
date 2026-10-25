# SPDX-License-Identifier: EUPL-1.2
"""Decision 0018 H1 to H3: health, readiness and metrics. The probes answer status only, by any Host; readiness covers
the store, the policy modules, the signer and the reconciler's age, and is computed at most every few seconds; the
management listener needs its token; metrics are a fixed list with bounded labels and no person in them."""
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from keyclerk import health, metrics

TOKEN = "t" * 40


class FakeStore:
    def __init__(self, breaks=(), fails=False):
        self.breaks, self.fails = list(breaks), fails

    def load(self):
        if self.fails:
            raise OSError("gone")
        return {"edges": []}

    def verify_log(self):
        return self.breaks

    def pending(self):
        return {"c1": {}, "c2": {}}


class FakeDesk:
    def __init__(self, store, broker_state=None):
        self.store, self.broker_state = store, broker_state


class FakeSigner:
    def __init__(self, up=True):
        self.up = up

    def ping(self):
        if not self.up:
            raise ConnectionRefusedError()


def runs(tmp_path: Path, ago: timedelta, **extra) -> Path:
    at = (datetime.now(timezone.utc) - ago).isoformat()
    (tmp_path / "runs.jsonl").write_text(json.dumps({"at": at, **extra}) + "\n", encoding="utf-8")
    return tmp_path


@pytest.fixture(autouse=True)
def clean_metrics():
    metrics.reset()
    yield
    metrics.reset()


def test_ready_when_store_policy_signer_and_reconcile_hold(tmp_path):
    r = health.Readiness(FakeDesk(FakeStore(), runs(tmp_path, timedelta(seconds=30))), FakeSigner(), max_age=900)
    d = r.detail()
    assert d["ready"] and set(d["checks"]) == {"store", "policy", "signer", "reconcile"}


@pytest.mark.parametrize("desk, signer, why", [
    (lambda p: FakeDesk(FakeStore(breaks=["log line 3 does not chain"])), FakeSigner(), "store"),
    (lambda p: FakeDesk(FakeStore(fails=True)), FakeSigner(), "store"),
    (lambda p: FakeDesk(FakeStore()), FakeSigner(up=False), "signer"),
    (lambda p: FakeDesk(FakeStore(), runs(p, timedelta(hours=2))), FakeSigner(), "reconcile"),
    (lambda p: FakeDesk(FakeStore(), p), FakeSigner(), "reconcile"),        # a state dir without any run
])
def test_not_ready_names_the_failing_check(tmp_path, desk, signer, why):
    d = health.Readiness(desk(tmp_path), signer, max_age=900).detail()
    assert not d["ready"] and not d["checks"][why]["ok"]
    assert all(ok["ok"] for k, ok in d["checks"].items() if k != why)


def test_a_downstream_broker_is_not_a_readiness_check(tmp_path):
    """Never downstream systems: no check reaches out to the broker; without a reconciler state there is no check."""
    d = health.Readiness(FakeDesk(FakeStore()), None, max_age=900).detail()
    assert d["ready"] and set(d["checks"]) == {"store", "policy"}


def test_readiness_is_computed_at_most_every_few_seconds():
    calls = []
    store = FakeStore()
    store.verify_log = lambda: calls.append(1) or []
    t = [100.0]
    r = health.Readiness(FakeDesk(store), None, max_age=900, clock=lambda: t[0])
    for _ in range(50):
        r.ready()
    assert len(calls) == 1
    t[0] += health.READY_TTL
    r.ready()
    assert len(calls) == 2


def _serve(readiness):
    srv = health.management_server(("127.0.0.1", 0), readiness, TOKEN)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _get(url, token=None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_the_management_listener_needs_its_token_and_is_read_only():
    srv, base = _serve(health.Readiness(FakeDesk(FakeStore()), None, max_age=900))
    try:
        assert _get(base + "/metrics")[0] == 401
        assert _get(base + "/metrics", "x" * 40)[0] == 401
        assert _get(base + "/metrics", TOKEN)[0] == 200
        status, body = _get(base + "/readyz", TOKEN)
        assert status == 200 and json.loads(body)["checks"]["store"]["ok"]
        req = urllib.request.Request(base + "/metrics", data=b"x", method="POST",
                                     headers={"Authorization": f"Bearer {TOKEN}"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == 405
    finally:
        srv.shutdown()


def test_a_short_management_token_is_refused():
    with pytest.raises(ValueError):
        health.management_server(("127.0.0.1", 0), health.Readiness(FakeDesk(FakeStore()), None), "short")


def test_metrics_are_the_fixed_list_with_bounded_labels(tmp_path):
    desk = FakeDesk(FakeStore(), runs(tmp_path, timedelta(seconds=10), findings=[1, 2, 3]))
    desk.edge_store = None
    r = health.Readiness(desk, None, max_age=900)
    health.register_gauges(desk, r)
    metrics.inc("keyclerk_changes_total", outcome="applied")
    metrics.inc("keyclerk_changes_total", outcome="idp:7c1f-ann")              # never a label value outside the list
    metrics.inc("keyclerk_edge_incidents_total", kind="attestation_failed")
    metrics.observe("keyclerk_check_seconds", 0.7)
    text = metrics.render()
    assert 'keyclerk_changes_total{outcome="applied"} 1' in text
    assert 'keyclerk_changes_total{outcome="other"} 1' in text and "7c1f" not in text
    assert 'keyclerk_check_seconds_bucket{le="1"} 1' in text and "keyclerk_check_seconds_count 1" in text
    assert "keyclerk_pending_changes 2" in text and "keyclerk_reconcile_drift 3" in text
    assert "keyclerk_ready 1" in text and 'keyclerk_build_info{version="' in text
    assert "keyclerk_edges_silent 0" in text                                  # no edges: none silent
    assert "keyclerk_signer_seconds_count" not in text                        # never called: no series yet
    names = {ln.split("{")[0].split(" ")[0] for ln in text.splitlines() if ln and not ln.startswith("#")}
    assert {n.removesuffix("_bucket").removesuffix("_sum").removesuffix("_count") for n in names} <= set(metrics.SPEC)
    with pytest.raises(ValueError):
        metrics.inc("keyclerk_changes_total", outcome="applied", person="idp:7c1f-ann")


def test_every_metric_says_what_alert_or_budget_it_serves():
    for name, (kind, help_, _) in metrics.SPEC.items():
        assert kind in ("counter", "gauge", "histogram") and len(help_) > 20, name
        assert not any(w in name for w in ("person", "anchor", "user", "email")), name


def test_the_signer_answers_ping_without_signing(tmp_path):
    from keyclerk import signer as S
    assert '"op": "ping"' in S.__doc__ or "{\"op\": \"ping\"}" in S.__doc__
    srcs = Path(S.__file__).read_text(encoding="utf-8")
    assert 'if op == "ping":' in srcs and '"ok": True' in srcs


def test_the_desk_listener_answers_probes_by_any_host_with_status_only(tmp_path):
    """An orchestrator probes by address, so the probes answer before the host check, and say only ok or ready."""
    from http.server import ThreadingHTTPServer
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from keyclerk import api
    from keyclerk.desk import Desk, Store
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, Path(__file__).resolve().parent / "fixtures" / "records.yaml"))
    states = {"ready": True}

    class R:
        def ready(self):
            return states["ready"]

    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.handler(desk, None, {"desk.test"}, (), False, (), R()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert _get(base + "/healthz") == (200, "ok\n")
        assert _get(base + "/readyz") == (200, "ready\n")
        states["ready"] = False
        assert _get(base + "/readyz") == (503, "not ready\n")
        assert _get(base + "/api/v1/me")[0] == 400                          # everything else still checks the Host
    finally:
        srv.shutdown()
