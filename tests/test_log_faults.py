# SPDX-License-Identifier: EUPL-1.2
"""The fault model of the desk on the change log (decision 0022 S5 step T8, operator 2026-10-25): each fault injected,
and what the desk does. No write is ever buffered; reads go on from the replica; a desk never signs; a replica that
cannot follow says why and heals from the signer; a replica ahead of its signer is refused, never trusted."""
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import FIXTURES

from keyclerk import health, metrics
from keyclerk.desk import Desk, Refusal, StoreFault
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store.log_desk import LogStore

ANN = {"anchor": "idp:7c1f-ann", "roles": []}
ADD = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5}


@pytest.fixture
def world(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer")
    store = LogStore(tmp_path / "desk", signer, FIXTURES / "records.yaml")
    w = {"key": key, "signer": signer, "store": store, "tmp": tmp_path}
    yield w
    for x in ("store", "signer"):
        try:
            w[x].close()
        except Exception:   # noqa: BLE001 - a test may have closed it already
            pass


class Down:
    """The signer, unreachable for proposals (a socket that refuses), answering everything else."""

    def __init__(self, signer):
        self.signer = signer

    def __getattr__(self, name):
        return getattr(self.signer, name)

    def propose(self, *a, **k):
        raise ConnectionRefusedError("the signer's socket refuses")


def test_a_stale_write_is_refused_whole_and_never_overwrites_another(world):
    """Two desks on one signer (the one-writer rule forbids it; the guard holds anyway): the second, behind, is refused
    with what to do, follows, and its next try lands on the newer state; the first desk's change stays."""
    other = LogStore(world["tmp"] / "other", world["signer"])
    try:
        Desk(world["store"]).propose(ANN, ADD)
        before = world["signer"].replica.size()
        with pytest.raises(Refusal, match="changed while this change was prepared"):
            other.commit({**other.load(), "memberships": other.load()["memberships"][1:]}, {"action": "x", "outcome": "applied"})
        assert world["signer"].replica.size() == before and other.store.head() == world["signer"].replica.head()
        r = Desk(other).propose(ANN, {**ADD, "anchor": "idp:bb11-kai"})   # its next try, on the state it now follows
        assert r["outcome"] == "applied" and world["signer"].replica.size() == before + 1
        finn = other.inward("idp:66cc-finn")
        assert any(m["member"].get("anchor") == finn for m in other.load()["memberships"])   # the first change stays
    finally:
        other.close()


def test_with_the_signer_down_reads_go_on_and_writes_are_refused_unbuffered(world):
    st = world["store"]
    st._signer = Down(world["signer"])
    before, size = st.load(), world["signer"].replica.size()
    with pytest.raises(Refusal, match="does not answer.*nothing was signed"):
        Desk(st).propose(ANN, ADD)
    assert st.load() == before and world["signer"].replica.size() == size
    st._signer = world["signer"]                                   # it answers again: nothing queued replays
    assert world["signer"].replica.size() == size
    assert Desk(st).propose(ANN, ADD)["outcome"] == "applied"


def test_a_desk_that_stopped_between_the_link_and_its_line_writes_it_at_start(world, monkeypatch):
    st = world["store"]
    real = LogStore.note
    calls = {"n": 0}

    def crash(self, entry):
        if "link" in entry and not entry.get("recovered"):
            calls["n"] += 1
            raise OSError("the process died here")
        return real(self, entry)
    monkeypatch.setattr(LogStore, "note", crash)
    with pytest.raises(OSError):
        Desk(st).propose(ANN, ADD)
    monkeypatch.setattr(LogStore, "note", real)
    seq = world["signer"].replica.size() - 1
    st.close()
    world["store"] = LogStore(world["tmp"] / "desk", world["signer"])
    last = world["store"].log(5)[-1]
    assert calls["n"] == 1 and last["link"] == seq and last["recovered"] and last["action"] == "add_member"
    assert not world["store"].verify_log()


def test_a_replica_restored_newer_than_its_signer_is_refused(world):
    st, s, tmp = world["store"], world["signer"], world["tmp"]
    st.close()
    s.close()
    shutil.copytree(tmp / "signer", tmp / "signer-backup")         # the signer's backup, before the next change
    s = Signer(world["key"], tmp / "signer")
    st = LogStore(tmp / "desk", s)
    Desk(st).propose(ANN, ADD)
    st.close()
    s.close()
    shutil.rmtree(tmp / "signer")
    shutil.copytree(tmp / "signer-backup", tmp / "signer")          # the signer restored from the older backup
    world["signer"] = Signer(world["key"], tmp / "signer")
    with pytest.raises(StoreFault, match="newer backup than its signer"):
        LogStore(tmp / "desk", world["signer"])
    for f in (tmp / "desk").glob("log*.db*"):                        # what the refusal says to do: rebuild it
        f.unlink()
    world["store"] = LogStore(tmp / "desk", world["signer"])
    assert world["store"].store.head() == world["signer"].replica.head()


def test_a_frozen_signer_leaves_the_desk_ready_and_read_only_and_says_so(world):
    st, s = world["store"], world["signer"]
    s._freeze("a test freeze")
    st.refresh()
    d = Desk(st)
    detail = health.Readiness(d, max_age=900).detail()
    assert detail["ready"] and "read-only" in detail["checks"]["log"]["why"]
    metrics.reset()
    health.register_gauges(d, health.Readiness(d, max_age=900))
    assert "keyclerk_signing_frozen 1" in metrics.render()
    with pytest.raises(SignerRefused, match="a test freeze"):
        d.propose(ANN, ADD)


def test_a_desk_that_cannot_follow_is_not_ready_says_why_and_heals(world):
    st, s = world["store"], world["signer"]

    class Broken(Down):
        def head(self):
            raise ConnectionResetError("the signer went away")
    st._signer = Broken(s)
    with pytest.raises(ConnectionResetError):
        st.refresh()
    d = Desk(st)
    detail = health.Readiness(d, max_age=900).detail()
    assert not detail["ready"] and "cannot follow" in detail["checks"]["log"]["why"] and st.follow_breaks() == 1
    st._signer = s
    st.refresh()
    assert st.follow_failure is None and health.Readiness(d, max_age=900).detail()["checks"]["log"]["ok"]


def test_a_refused_timer_step_is_an_alarm(tmp_path, monkeypatch):
    from test_visits import ANN as A, entry, register, visit_desk
    d = visit_desk(tmp_path, "sqlite")
    try:
        register(d)
        d.test_clock.at("11:05")
        entry(d, "P1", "qr", vehicle=True)
        d.propose({"anchor": A, "roles": []}, {"action": "acknowledge_arrival", "visit_id": "V-example-0001", "party": "P1"})
        monkeypatch.setattr(Desk, "_evaluate", lambda self, doc, add: ("refused", ["a test refusal"], None))
        metrics.reset()
        d.test_clock.at("11:20")
        assert d.tick()
        assert "keyclerk_timer_refused_total 1" in metrics.render()
    finally:
        d.store.close()
        d.test_signer.close()
