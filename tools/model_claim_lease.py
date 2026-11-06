# SPDX-License-Identifier: EUPL-1.2
"""Decision 0032 points 30 to 38, version 2: the claim-lease model of docs/specs/ClaimLease.tla, explored exhaustively in
Python so every test run checks it without Java. One lease resting on one claim; a desk that signs bundles which travel
to an edge and can be held back and delivered late (second adversarial review M1); an edge whose wall clock the adversary holds,
which it reboots and cuts off, and which accepts a bundle within the protocol's skew; an issuer that revokes and whose
status lists the desk may receive late (M9); an officer whose revocation lives in the signer's log (M2); a desk restored
from an older backup. The boot clock may freeze (a paused virtual machine) while the wall clock is honest, and the wall
clock may be set while the boot clock runs; at every wake the edge records a new anchor, the later raw reading. That one
clock at a time is tampered with, and that the edge's state cannot be rolled back, are the deployment's assumptions: the
variants BothClocks and EdgeReverted show what breaks without them (M3), NoRatchet and RatchetTrusted what breaks
without the ratchet or with a ratchet that records the skew-tolerant reading.

Properties, with S the protocol's skew (an end is acted on at most 2 S late, edge protocol 1.5 section 1):
- BoundedExposure: the lease is never usable at or after its own end + 2 S, its claim's end + 2 S, or, once the issuer
  revoked the claim, the revocation + the type's maximum offline reliance + 2 S.
- OfficerBounded: once the officer revoked the lease, it is never usable at or after the revocation + the horizon + 2 S
  (what a cut-off edge holds was issued before the revocation and ends within the horizon).
- NoResurrect: once the edge applied a bundle issued after the officer's revocation, the lease is never usable again.

    python tools/model_claim_lease.py        (each case at its bounds below; the TLC-only ones are named)
    java -cp tla2tools.jar tlc2.TLC -deadlock -config docs/specs/ClaimLease.cfg docs/specs/ClaimLease.tla
"""
from __future__ import annotations

import argparse
import sys
from collections import deque
from typing import NamedTuple

SMALL = {"max_t": 3, "lend": 1, "valid": 1, "horizon": 1, "reliance": 1, "skew": 1, "max_serial": 1}
TWO = {**SMALL, "max_serial": 2}                              # a bundle held back while a later one is delivered
LONGER = {"max_t": 4, "lend": 3, "valid": 3, "horizon": 2, "reliance": 1, "skew": 1, "max_serial": 1}   # reliance < H < end
TLC = {"max_t": 5, "lend": 3, "valid": 3, "horizon": 2, "reliance": 1, "skew": 1, "max_serial": 2}      # ClaimLease.cfg
# name: (variant, the properties any of which it must break (() when all must hold), the bounds this explorer checks it
# at on every test run, or None when only TLC's bounds reach it: docs/specs/ClaimLease-<variant>.cfg)
CASES = {
    "the rule as drafted": ("ok", (), SMALL),
    "edge protocol 1.4's time rule: the later of the clock and the newest signed time (T1)":
        ("BrokenTime", ("BoundedExposure", "OfficerBounded"), SMALL),
    "the raw wall clock recorded at a bundle, not the trusted time (M1 within a boot)":
        ("AnchorRawWall", ("BoundedExposure", "OfficerBounded"), TWO),
    "after a reboot any bundle above the floor counts as fresh (M1 across a reboot)":
        ("NoFreshAfterReboot", ("BoundedExposure", "OfficerBounded"), SMALL),
    "a lease live after a reboot (T1)": ("NoRebootLock", ("BoundedExposure", "OfficerBounded", "NoResurrect"), SMALL),
    "a fold without the status-freshness bound (T4)": ("NoReliance", ("BoundedExposure",), LONGER),
    "a status list stamped with the fetch time, not its own (M9)": ("FetchStamped", ("BoundedExposure",), None),
    "a desk restore that forgets the officer's revocation (M2)": ("RestoreForgets", ("OfficerBounded",), None),
    "no anchor recorded at each wake: a frozen boot clock, then the wall set back (found by the platform model's simulation)":
        ("NoRatchet", ("BoundedExposure", "OfficerBounded"), LONGER),
    "each wake records the skew-tolerant trusted time: the lag compounds": ("RatchetTrusted", ("BoundedExposure",
                                                                                            "OfficerBounded"), LONGER),
    "both clocks tampered at once (the stated limit)": ("BothClocks", ("BoundedExposure", "OfficerBounded"), SMALL),
    "the edge's state rolled back to an earlier snapshot (M3)": ("EdgeReverted", ("BoundedExposure", "OfficerBounded",
                                                                                   "NoResurrect"), SMALL),
}


def broke_as_intended(bad: str | None, must_break: tuple) -> bool:
    return bad is None if not must_break else bool(bad) and bad.startswith(must_break)


class B(NamedTuple):            # a bundle in flight
    serial: int
    issued: int
    fold: int
    revokes: bool                # issued after a revocation the desk knew of: the lease ends at its issue
    officer: bool                # issued after the officer's revocation


class S(NamedTuple):
    now: int
    wall: int
    boot: int
    boot_valid: bool             # a bundle verified in this boot
    anchor: int                  # the trusted time recorded at the last verified bundle
    boot_at_verify: int
    signed_t: int                # the newest signed time applied
    edge_serial: int
    edge_end: int
    floor_end: int               # the edge's end floor: a lease ended once never ends later
    connected: bool
    issuer_revoked: bool
    revoked_at: int
    status_at: int               # the issue time of the newest status list the desk holds
    sees: bool
    officer_revoked: bool
    officer_ever: bool
    officer_at: int
    officer_delivered: bool
    next_serial: int
    inflight: frozenset
    paused: bool = False         # the boot clock frozen (a paused virtual machine)


class Model:
    def __init__(self, max_t, lend, valid, horizon, reliance, skew, max_serial, variant="ok", limit=2_000_000):
        self.max_t, self.lend, self.valid, self.h, self.rel, self.skew = max_t, lend, valid, horizon, reliance, skew
        self.max_serial, self.variant, self.limit = max_serial, variant, limit
        self.inf = max_t + 100

    def trusted(self, s: S) -> int:
        if self.variant == "BrokenTime":
            return max(s.wall, s.signed_t)
        if not s.boot_valid:
            return s.wall
        by_boot = s.anchor + s.boot - s.boot_at_verify
        return by_boot if by_boot > s.wall + self.skew else s.wall

    def can_use(self, s: S) -> bool:
        return s.edge_end > self.trusted(s) and (s.boot_valid or self.variant == "NoRebootLock")

    def fold(self, s: S) -> int:
        if s.officer_revoked or s.sees:
            return s.now
        bound = min(self.lend, self.valid, s.now + self.h)
        return bound if self.variant == "NoReliance" else min(bound, s.status_at + self.rel)

    def bad(self, s: S) -> str | None:
        if not self.can_use(s):
            return None
        late = 2 * self.skew
        if s.now >= self.lend + late or s.now >= self.valid + late:
            return "BoundedExposure: usable after the lease's or the claim's end"
        if s.issuer_revoked and s.now >= s.revoked_at + self.rel + late:
            return "BoundedExposure: usable after the revocation plus the offline reliance"
        if s.officer_ever and s.now >= s.officer_at + self.h + late:
            return "OfficerBounded: usable past the horizon after the officer's revocation"
        if s.officer_delivered:
            return "NoResurrect: usable after the edge applied the officer's revocation"
        return None

    def nexts(self, s: S):
        r, v = s._replace, self.variant
        if s.now < self.max_t:                         # a wake: real time, the wall clock, the boot clock unless frozen
            nxt = r(now=s.now + 1, boot=s.boot + (0 if s.paused else 1), wall=min(s.wall + 1, self.max_t))
            if nxt.boot_valid and v != "NoRatchet":    # every wake records a new anchor (edge protocol 1.5, section 1)
                by_boot = nxt.anchor + nxt.boot - nxt.boot_at_verify
                nxt = nxt._replace(anchor=self.trusted(nxt) if v == "RatchetTrusted" else max(by_boot, nxt.wall),
                                   boot_at_verify=nxt.boot)
            yield "Tick", nxt
        one_at_a_time = v != "BothClocks"              # the deployment's assumption: never both clocks tampered at once
        if s.paused:
            yield "Thaw", r(paused=False)
        elif not one_at_a_time or s.wall == s.now:     # the boot clock freezes (a paused VM) only while the wall is honest
            yield "Freeze", r(paused=True)
        for w in range(self.max_t + 1):
            if w != s.wall and not (one_at_a_time and s.paused):
                yield f"SetWall {w}", r(wall=w)
        yield "Reboot", r(boot=0, boot_valid=False)
        yield "Cut", r(connected=not s.connected)
        if not s.issuer_revoked:
            yield "IssuerRevoke", r(issuer_revoked=True, revoked_at=s.now)
        for t in range(s.status_at, s.now + 1):       # a status list issued at t reaches the desk (an older one than
                                                      # the desk holds changes nothing)
            sees = s.sees or (s.issuer_revoked and s.revoked_at <= t)
            at = s.now if v == "FetchStamped" else max(s.status_at, t)
            yield f"Fetch {t}", r(status_at=at, sees=sees)
        if not s.officer_revoked:
            yield "OfficerRevoke", r(officer_revoked=True, officer_ever=True,
                                     officer_at=s.officer_at if s.officer_ever else s.now)
        for old in range(s.status_at + 1):            # an older backup: an older list, with what it said
            yield f"Restore {old}", r(status_at=old, sees=s.issuer_revoked and s.revoked_at <= old,
                                      officer_revoked=s.officer_revoked and v != "RestoreForgets")
        if s.next_serial <= self.max_serial:
            b = B(s.next_serial, s.now, self.fold(s), s.officer_revoked or s.sees, s.officer_revoked)
            yield f"Issue {b.serial}", r(next_serial=s.next_serial + 1, inflight=s.inflight | {b})
        if v == "EdgeReverted" and s.boot_valid:       # the edge rolled back: its floors and its boot clock with it
            yield "Revert", r(edge_serial=0, signed_t=0, floor_end=self.inf, boot=s.boot_at_verify)
        if s.connected:
            for b in s.inflight:
                yield from self.deliver(s, b)

    def deliver(self, s: S, b: B):
        v, now_t = self.variant, self.trusted(s)
        if b.serial <= s.edge_serial or b.issued < s.signed_t or b.issued > now_t + self.skew:
            return                                     # the edge's floors and its issue-time check
        fresh = b.issued == s.now                      # answers a nonce the edge sent in this boot (no delay)
        if not s.boot_valid and v != "NoFreshAfterReboot" and not fresh:
            return
        if v == "AnchorRawWall":
            anchor = s.wall
        elif s.boot_valid:
            anchor = now_t
        else:
            anchor = s.wall if v == "NoFreshAfterReboot" else max(s.wall, b.issued)
        floor = 0 if b.revokes else s.floor_end       # a bundle is complete: a revoked lease is absent, ended at once
        yield f"Deliver {b.serial}", s._replace(
            edge_serial=b.serial, signed_t=b.issued, anchor=anchor, boot_at_verify=s.boot, boot_valid=True,
            edge_end=min(b.fold, floor), floor_end=floor, officer_delivered=s.officer_delivered or b.officer)

    def run(self):
        init = S(0, 0, 0, False, 0, 0, 0, 0, 0, self.inf, True, False, 0, 0, False, False, False, 0, False, 1,
                 frozenset())
        seen, queue = {init: None}, deque([init])
        while queue:
            s = queue.popleft()
            why = self.bad(s)
            if why:
                trace, x = [], s
                while x is not None:
                    trace.append(x)
                    x = seen[x][1] if seen[x] else None
                return why, [seen[t][0] if seen[t] else "Init" for t in reversed(trace)], len(seen)
            for label, n in self.nexts(s):
                if n not in seen:
                    seen[n] = (label, s)
                    queue.append(n)
                    if len(seen) > self.limit:
                        return "state limit reached", [], len(seen)
        return None, [], len(seen)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.parse_args(argv)
    ok = True
    for name, (variant, must_break, bounds) in CASES.items():
        if bounds is None:
            print(f"TLC  {name}: only TLC's bounds reach it (docs/specs/ClaimLease-{variant}.cfg)")
            continue
        bad, trace, states = Model(**bounds, variant=variant).run()
        if bad and bad.startswith("state limit"):
            print(f"ERROR {name}: {bad} ({states} states)")
            ok = False
            continue
        held = broke_as_intended(bad, must_break)
        ok &= held
        print(f"{'OK  ' if held else 'FAIL'} {name}: {bad or 'holds'} ({states} states)"
              + (f"\n     {' > '.join(trace)}" if bad else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
