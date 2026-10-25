# SPDX-License-Identifier: EUPL-1.2
"""Physical access for the access lease: the shared core, the PACS connector contract
against a simulated head-end, and the OSDP controller against libosdp's own peripheral device over a secure channel.
libosdp is a pinned dev requirement, so the OSDP tests run on every machine that runs the gate; nothing is skipped."""
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk.piam import pacs  # noqa: E402
from keyclerk.piam.core import Allowlist, RollCall, badge_hash, records_from_leases  # noqa: E402
from keyclerk.piam.osdp_controller import Controller, Door, LibOsdpTransport, SimTransport  # noqa: E402

KEY = b"test-site-badge-key-not-a-secret"
T0 = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
CARD = bytes([0x12, 0x34, 0x56, 0x78])
CARD2 = bytes([0x9A, 0xBC, 0xDE, 0xF0])

LEASES = [
    {"lease_id": "L-t1-0001", "anchor": "ext:anna", "start": "2026-10-21T07:00:00Z", "end": "2026-10-21T17:00:00Z"},
    {"lease_id": "L-t1-0002", "anchor": "ext:bob", "start": "2026-10-01T00:00:00Z", "end": "2026-10-20T00:00:00Z"},
]
PHYSICAL = [
    {"lease_id": "L-t1-0001", "badge": badge_hash(KEY, CARD), "sites": ["hq"], "areas": ["lobby", "lab"]},
    {"lease_id": "L-t1-0002", "badge": badge_hash(KEY, CARD2), "sites": ["hq"]},
    {"lease_id": "L-none-9999", "badge": badge_hash(KEY, b"\x00"), "sites": ["hq"]},
]


def _allow(revoked=()):
    return Allowlist(records_from_leases(LEASES, PHYSICAL), set(revoked))


def test_a_badge_is_granted_only_inside_its_lease_site_and_area():
    a = _allow()
    h = badge_hash(KEY, CARD)
    assert a.decide(h, "hq", "lab", T0).granted
    assert a.decide(h, "hq", "vault", T0).reason == "outside-area"
    assert a.decide(h, "branch", "lab", T0).reason == "outside-site"
    assert a.decide(h, "hq", "lab", T0 + timedelta(hours=9)).reason == "lease-ended"
    assert a.decide(badge_hash(KEY, CARD2), "hq", "lobby", T0).reason == "lease-ended"
    assert a.decide(badge_hash(KEY, b"\x00"), "hq", "lobby", T0).reason == "unknown-badge"   # no lease, no badge
    assert _allow({"L-t1-0001"}).decide(h, "hq", "lab", T0).reason == "lease-revoked"


def test_badge_ids_are_kept_only_as_keyed_hashes():
    recs = records_from_leases(LEASES, PHYSICAL)
    assert all(r.badge.startswith("hmac-sha256:") and CARD.hex() not in r.badge for r in recs)
    assert badge_hash(KEY, CARD) != badge_hash(b"other-site-key", CARD)


def test_the_pacs_holds_the_lease_dates_and_enforces_them_when_the_it_link_is_cut():
    sim = pacs.SimulatedPacs(foreign={"staff:carol": {"source": "pacs", "credential": "x", "levels": ["hq"]}})
    want = pacs.desired(records_from_leases(LEASES, PHYSICAL), set())
    p = pacs.plan(want, sim.cardholders(), T0)
    assert p["create"] == ["ext:anna", "ext:bob"] and not p["findings"]
    pacs.apply(sim, want, p, T0)
    assert pacs.plan(want, sim.cardholders(), T0)["create"] == []   # idempotent
    # the IT link is cut from here on: no more plans or applies; the door still decides on the stored dates
    h = badge_hash(KEY, CARD)
    assert sim.badge_read(h, "hq", "lab", T0).granted
    assert sim.badge_read(h, "hq", "lab", T0 + timedelta(hours=10)).reason == "lease-ended"
    ev = sim.events()
    assert [e["granted"] for e in ev] == [True, False]


def test_a_revoked_lease_is_expired_in_the_pacs_and_undeclared_credentials_are_findings():
    sim = pacs.SimulatedPacs(foreign={"staff:carol": {"source": "pacs", "credential": "x", "levels": ["hq"]}})
    recs = records_from_leases(LEASES, PHYSICAL)
    want = pacs.desired(recs, set())
    pacs.apply(sim, want, pacs.plan(want, sim.cardholders(), T0), T0)
    sim.holders["ext:mallory"] = {"source": pacs.SOURCE, "credential": "hmac-sha256:ff", "levels": ["hq"],
                                  "activation": T0, "expiry": T0 + timedelta(days=30)}   # planted under our tag
    want2 = pacs.desired(recs, {"L-t1-0001"})
    p = pacs.plan(want2, sim.cardholders(), T0)
    assert p["expire"] == ["ext:anna", "ext:mallory"]
    assert [f["anchor"] for f in p["findings"]] == ["ext:mallory"]
    assert "staff:carol" not in p["expire"]   # the PACS's own cardholders are never touched
    pacs.apply(sim, want2, p, T0)
    assert sim.badge_read(badge_hash(KEY, CARD), "hq", "lab", T0 + timedelta(minutes=1)).reason in ("credential-disabled", "lease-ended")


def test_the_osdp_controller_decides_locally_and_keeps_the_roll_call():
    t = SimTransport()
    events = []
    now = [T0]
    door = Door("lab-door", "hq", "lab", pd=101, entry_reader=0, exit_reader=1, strike_output=0)
    c = Controller([door], _allow(), KEY, t, events.append, lambda: now[0])
    t.reads = [(101, 0, CARD)]
    assert c.step()[0].granted and c.roll.on_site("hq") == ["ext:anna"]
    assert ("output", 101, 0, 3000) in t.sent and ("led", 101, 0, "green") in t.sent
    t.reads = [(101, 0, CARD2)]
    assert not c.step()[0].granted and ("led", 101, 0, "red") in t.sent
    now[0] = T0 + timedelta(hours=10)                     # the lease ended while Anna is inside
    assert c.reload(_allow()) == ["ext:anna"]             # the desk is told who is still on site
    t.reads = [(101, 1, CARD)]
    d = c.step()[0]
    assert d.granted and d.reason == "exit-after-end" and c.roll.on_site("hq") == []   # leaving is never blocked
    assert events[0]["class_uid"] == 3002 and events[0]["status"] == "Success" and events[1]["status"] == "Failure"
    assert all("12345678" not in str(e) for e in events)   # raw badge ids never leave the controller


class _Pipe:
    def __init__(self):
        self.buf, self.lock = deque(), threading.Lock()


def _channel(rx, tx):
    import osdp

    class Mem(osdp.Channel):
        def read(self, n):
            with rx.lock:
                return bytes(rx.buf.popleft() for _ in range(min(n, len(rx.buf))))

        def write(self, buf):
            with tx.lock:
                tx.buf.extend(buf)
            return len(buf)

        def flush(self):
            pass

    return Mem()


@pytest.fixture()
def osdp_pair():
    import osdp
    a, b = _Pipe(), _Pipe()
    key = osdp.KeyStore.gen_key()
    cap = osdp.PDCapabilities([(osdp.Capability.LEDControl, 1, 1), (osdp.Capability.AudibleControl, 1, 1),
                               (osdp.Capability.OutputControl, 1, 1)])
    pd = osdp.PeripheralDevice(osdp.PDInfo(101, _channel(a, b), scbk=key, flags=[osdp.LibFlag.EnforceSecure]), cap,
                               log_level=osdp.LogLevel.Error)
    cp = osdp.ControlPanel([osdp.PDInfo(101, _channel(b, a), scbk=key, flags=[osdp.LibFlag.EnforceSecure])],
                           log_level=osdp.LogLevel.Error)
    pd.start()
    cp.start()
    try:
        assert cp.online_wait_all(timeout=10), "the reader did not come online over the secure channel"
        yield osdp, cp, pd
    finally:
        cp.teardown()
        pd.teardown()


def test_the_osdp_controller_works_against_libosdps_reader_over_a_secure_channel(osdp_pair):
    osdp, cp, pd = osdp_pair
    events = []
    door = Door("lab-door", "hq", "lab", pd=101, entry_reader=1, strike_output=0)
    c = Controller([door], _allow(), KEY, LibOsdpTransport(cp, [101]), events.append, lambda: T0)

    def read(card):
        pd.submit_event({"event": osdp.Event.CardRead, "reader_no": 1, "direction": 0, "length": 8 * len(card),
                         "format": osdp.CardFormat.Unspecified, "data": card})
        deadline = time.time() + 5
        while time.time() < deadline:
            got = c.step(timeout=0.3)
            if got:
                return got[0]
        pytest.fail("no card read reached the controller")

    def commands():
        out = []
        while (cmd := pd.get_command(timeout=1)) is not None:
            out.append(cmd)
        return out

    assert read(CARD).granted
    cmds = commands()
    assert any(x["command"] == osdp.Command.LED and x["on_color"] == osdp.CommandLEDColor.Green for x in cmds)
    assert any(x["command"] == osdp.Command.Output and x["output_no"] == 0 for x in cmds)
    assert not read(CARD2).granted
    cmds = commands()
    assert any(x["command"] == osdp.Command.LED and x["on_color"] == osdp.CommandLEDColor.Red for x in cmds)
    assert any(x["command"] == osdp.Command.Buzzer for x in cmds)
    assert [e["status"] for e in events] == ["Success", "Failure"] and c.roll.on_site("hq") == ["ext:anna"]


def test_roll_call_lists_who_is_inside_per_site():
    r = RollCall()
    r.record("hq", "a", "entry", T0)
    r.record("hq", "b", "entry", T0)
    r.record("hq", "a", "exit", T0)
    assert r.on_site("hq") == ["b"] and r.end_lease("b") == ["hq"]
