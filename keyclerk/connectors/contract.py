# SPDX-License-Identifier: EUPL-1.2
"""The KeyClerk connector contract.

Every connector, source (people and attributes in) or target (grants out), has the same operations:
  describe()                  name, version, role, capabilities, the data classes it touches
  validate(config)            what is wrong with a configuration, before anything runs
  schema()                    the shape of the items it reads or writes
  read_full()                 every item, keyed; mandatory and authoritative
  read_delta(cursor)          (items, next cursor); only a speed-up, never the authority
  verify_event(raw, headers)  a verified change notification, or None
  observe()                   events since the last call (door reads, sign-ins), for the roll call and the event store
  plan(desired, observed)     pure and deterministic: what would change, plus findings
  apply(plan, key, dry_run)   applies a plan once per idempotency key; dry run is the default
  expire(key, at)             ends one item now (a target with native expiry also stores the end)

Rules: a connector holds short-lived credentials only; it never touches an item outside its managed scope; reads are
untrusted; every connector KeyClerk did not write runs out of process; a rate budget bounds its calls.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Capabilities:
    role: str                                   # source, target or both
    objects: tuple = ("person",)                # person, membership, cardholder, credential
    delta: bool = False
    events: bool = False
    expiry_native: bool = False                 # the target itself stores and enforces an end (a PACS, a door controller)
    rate_per_minute: int = 600                  # the connector's call budget


class RateBudget:
    """A token bucket: a connector's calls per minute, so a full read never trips quotas or lockouts."""

    def __init__(self, per_minute: int, clock=time.monotonic):
        self.capacity, self.tokens, self.clock, self.last = per_minute, float(per_minute), clock, clock()

    def take(self, n: int = 1) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.capacity / 60)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class BudgetExceeded(Exception):
    pass


@dataclass
class Connector:
    """Shared behaviour; a concrete connector supplies the item operations."""
    name: str = "connector"
    version: str = "0.1"
    caps: Capabilities = field(default_factory=lambda: Capabilities("source"))
    data_classes: tuple = ("operational",)
    applied: dict = field(default_factory=dict)          # idempotency key -> result

    def __post_init__(self):
        self.budget = RateBudget(self.caps.rate_per_minute)

    def spend(self, n: int = 1) -> None:
        if not self.budget.take(n):
            raise BudgetExceeded(self.name)

    def describe(self) -> dict:
        return {"name": self.name, "version": self.version, "role": self.caps.role, "objects": list(self.caps.objects),
                "delta": self.caps.delta, "events": self.caps.events, "expiry_native": self.caps.expiry_native,
                "rate_per_minute": self.caps.rate_per_minute, "data_classes": list(self.data_classes)}

    def validate(self, config: dict) -> list[str]:
        return []

    def schema(self) -> dict:
        return {}

    def read_delta(self, cursor):
        raise NotImplementedError(f"{self.name} declares no delta capability")

    def verify_event(self, raw: bytes, headers: dict):
        return None

    def observe(self) -> list[dict]:
        return []

    def expire(self, key, at: datetime) -> None:
        raise NotImplementedError(f"{self.name} has no expire")

    def apply(self, plan: dict, key: str, dry_run: bool = True) -> dict:
        """Apply once per idempotency key; a dry run changes nothing and reports what would happen."""
        if dry_run:
            return {"dry_run": True, "would": plan}
        if key in self.applied:
            return self.applied[key]
        result = self._apply(plan)
        self.applied[key] = result
        return result

    def _apply(self, plan: dict) -> dict:
        raise NotImplementedError


class MembershipTarget(Connector):
    """A target whose items are (group, anchor) memberships under managed group prefixes; everything else is never
    touched (KeyClerk never removes what it did not create)."""
    managed: tuple = ("/grants/", "/leases/", "/groups/")   # the reconciler's groups: grants, leases, delegated groups

    def is_managed(self, group: str) -> bool:
        return group.startswith(self.managed)

    def plan(self, desired: set, observed: set) -> dict:
        want = {(g, a) for g, a in desired if self.is_managed(g)}
        have = {(g, a) for g, a in observed if self.is_managed(g)}
        refused = sorted({(g, a) for g, a in desired if not self.is_managed(g)})
        return {"add": sorted(want - have), "remove": sorted(have - want),
                "findings": [{"group": g, "anchor": a, "why": "outside the managed prefixes, refused"} for g, a in refused]}


def contract_check(conn: Connector, desired, observe_after=None) -> list[str]:
    """The contract tests every connector must pass (connectors.rules; proof_contract.adding_a_method's
    sibling for connectors): describe is complete, plan is pure and deterministic, a dry run changes nothing, apply is
    idempotent per key, and after apply a full read shows the desired managed state."""
    errs = []
    d = conn.describe()
    for k in ("name", "version", "role", "objects", "rate_per_minute", "data_classes"):
        if k not in d:
            errs.append(f"describe lacks {k}")
    if d.get("role") not in ("source", "target", "both"):
        errs.append("role must be source, target or both")
    if d.get("role") == "source":
        return errs
    before = conn.read_full()
    p1, p2 = conn.plan(desired, before), conn.plan(desired, before)
    if p1 != p2:
        errs.append("plan is not deterministic")
    if conn.read_full() != before:
        errs.append("plan changed the target")
    conn.apply(p1, "contract-1")                     # dry run by default
    if conn.read_full() != before:
        errs.append("a dry run changed the target")
    conn.apply(p1, "contract-1", dry_run=False)
    after = conn.read_full()
    conn.apply(p1, "contract-1", dry_run=False)      # the same key again: no second effect
    if conn.read_full() != after:
        errs.append("apply is not idempotent per key")
    again = conn.plan(desired, after)
    if any(again.get(k) for k in ("add", "remove", "create", "update", "expire")):
        errs.append(f"after apply the plan is not empty: {again}")
    return errs
