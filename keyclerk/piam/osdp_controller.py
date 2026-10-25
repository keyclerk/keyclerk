# SPDX-License-Identifier: EUPL-1.2
"""OSDP controller for sites without a PACS: this code is the control panel for the readers of a small site
(an access enclave). OSDP carries card reads, keypad input, LED, buzzer and outputs between a reader (peripheral
device) and its controller; the credential database and the decision live here, with the lease ends from the signed
bundle, so the door decides locally when the site is cut off.

Two transports behind one interface: libosdp's control panel (secure channel with a per-reader key) on a serial line
or any byte channel, and a pure-Python simulator. Each door names its readers: one for entry and, if present, one for
exit; the roll call follows from granted reads. A grant flashes the LED green and pulses the strike output where the
reader or I/O module offers OutputControl; a denial flashes red and beeps.

Not here, by design: life safety (egress and fire release stay with the door hardware), anti-passback and alarms
(door forced or held), which a PACS provides and an enclave either lacks or gets from its door hardware.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Protocol

from keyclerk.piam.core import Allowlist, Decision, RollCall, badge_hash, ocsf_event


@dataclass(frozen=True)
class Door:
    name: str
    site: str
    area: str
    pd: int                 # OSDP address of the reader
    entry_reader: int = 0
    exit_reader: int | None = None
    strike_output: int | None = None   # output number on the PD that drives the strike, if it has one


class Transport(Protocol):
    def card_reads(self, timeout: float) -> list[tuple[int, int, bytes]]: ...   # (pd, reader, raw card data)
    def feedback(self, pd: int, reader: int, granted: bool) -> None: ...
    def pulse(self, pd: int, output: int, ms: int) -> None: ...


@dataclass
class SimTransport:
    reads: list = field(default_factory=list)
    sent: list = field(default_factory=list)

    def card_reads(self, timeout: float) -> list:
        out, self.reads = self.reads, []
        return out

    def feedback(self, pd: int, reader: int, granted: bool) -> None:
        self.sent.append(("led", pd, reader, "green" if granted else "red"))

    def pulse(self, pd: int, output: int, ms: int) -> None:
        self.sent.append(("output", pd, output, ms))


class LibOsdpTransport:
    """libosdp control panel. cp is an osdp.ControlPanel already started (secure channel keys per reader come from
    OpenBao at start, never from git)."""

    def __init__(self, cp, pds: list[int]):
        import osdp
        self.osdp, self.cp, self.pds = osdp, cp, pds

    def card_reads(self, timeout: float) -> list:
        out = []
        for pd in self.pds:
            e = self.cp.get_event(pd, timeout=timeout)
            if e and e.get("event") == self.osdp.Event.CardRead:
                out.append((pd, e["reader_no"], bytes(e["data"])))
        return out

    def feedback(self, pd: int, reader: int, granted: bool) -> None:
        o = self.osdp
        self.cp.submit_command(pd, {
            "command": o.Command.LED, "reader": reader, "led_number": 0, "control_code": 1,
            "on_count": 10, "off_count": 10, "timer_count": 20, "temporary": True,
            "on_color": o.CommandLEDColor.Green if granted else o.CommandLEDColor.Red,
            "off_color": o.CommandLEDColor.Black})
        if not granted:
            self.cp.submit_command(pd, {"command": o.Command.Buzzer, "reader": reader, "control_code": 2,
                                        "on_count": 2, "off_count": 2, "rep_count": 2})

    def pulse(self, pd: int, output: int, ms: int) -> None:
        o = self.osdp
        self.cp.submit_command(pd, {"command": o.Command.Output, "output_no": output, "control_code": 5,
                                    "timer_count": max(1, ms // 100)})


class Controller:
    def __init__(self, doors: list[Door], allowlist: Allowlist, key: bytes, transport: Transport,
                 emit: Callable[[dict], None], clock: Callable[[], datetime]):
        self.doors = {(d.pd, r): (d, "entry" if r == d.entry_reader else "exit")
                      for d in doors for r in ([d.entry_reader] + ([d.exit_reader] if d.exit_reader is not None else []))}
        self.allowlist, self.key, self.t, self.emit, self.clock = allowlist, key, transport, emit, clock
        self.roll = RollCall()

    def reload(self, allowlist: Allowlist) -> list[str]:
        """A new bundle: the allowlist is replaced in one step; holders of ended leases still on site are returned."""
        old = {r.anchor for r in self.allowlist.by_badge.values()}
        self.allowlist = allowlist
        now = self.clock()
        still = {r.anchor for r in allowlist.by_badge.values() if r.start <= now < r.end and r.lease_id not in allowlist.revoked}
        return sorted(a for a in old - still if self.roll.end_lease(a))

    def step(self, timeout: float = 0.2) -> list[Decision]:
        out = []
        for pd, reader, raw in self.t.card_reads(timeout):
            door, direction = self.doors.get((pd, reader), (None, None))
            at = self.clock()
            if door is None:
                d = Decision(False, "unknown-reader")
                self.emit(ocsf_event(d, "?", "?", reader, "entry", at))
                out.append(d)
                continue
            d = self.allowlist.decide(badge_hash(self.key, raw), door.site, door.area, at)
            if direction == "exit" and not d.granted and d.record is not None and d.reason in ("lease-ended", "lease-revoked"):
                d = Decision(True, "exit-after-end", d.record)   # leaving is never blocked by an ended lease
            self.t.feedback(pd, reader, d.granted)
            if d.granted:
                if door.strike_output is not None:
                    self.t.pulse(pd, door.strike_output, 3000)
                self.roll.record(door.site, d.record.anchor, direction, at)
            self.emit(ocsf_event(d, door.site, door.name, reader, direction, at))
            out.append(d)
        return out
