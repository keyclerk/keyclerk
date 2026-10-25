# SPDX-License-Identifier: EUPL-1.2
"""PACS connector contract: the lease is pushed down to a PACS head-end so its field controllers enforce the
lease end at the door, also when the IT link is cut.

Desired state per badge record: a cardholder keyed by the lease's anchor, one credential (the badge, as the PACS knows
it; we keep only its keyed hash), one access level per site or area, an activation date (lease start) and an expiry
date (lease end), stored in the PACS. The plan is idempotent, like tools/grants.py plan: create what is missing, update
what differs, expire what ended or was revoked in the same step as the logical access, and flag what the PACS holds
under our management that the leases do not (a finding). Cardholders the PACS holds outside our management (its own
staff, its own visitors) are never touched: we manage only cardholders tagged with our source.

Candidate head-ends and their public interfaces (next, not built): Gallagher Command Centre REST API (cardholders,
cards, access groups, events), LenelS2 OpenAccess (REST: cardholders, badges with activate and deactivate dates,
events), Genetec Security Center (Web SDK; credentials with an expiration), Nedap AEOS (web services API), Paxton Net2
(local REST API, licensed), and PSIA PLAI for head-ends that conform. ONVIF Profile A (credentials, access rules,
schedules) and Profile C (doors and events) where the controller speaks ONVIF.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from keyclerk.piam.core import Allowlist, BadgeRecord, Decision

SOURCE = "keyclerk-lease"   # tag on every cardholder this connector manages


def level(site: str, area: str | None = None) -> str:
    return f"{site}:{area}" if area else site


def desired(records: list[BadgeRecord], revoked_leases: set[str]) -> dict:
    """anchor -> what the PACS must hold. Revoked leases are not desired: their cardholder is expired."""
    out = {}
    for r in records:
        if r.lease_id in revoked_leases:
            continue
        levels = sorted(level(s, a) for s in r.sites for a in (r.areas or [None]))
        out[r.anchor] = {"credential": r.badge, "levels": levels, "activation": r.start, "expiry": r.end,
                         "lease_id": r.lease_id}
    return out


class PacsConnector(Protocol):
    def cardholders(self) -> dict: ...                     # anchor -> {source, credential, levels, activation, expiry}
    def upsert(self, anchor: str, holder: dict) -> None: ...
    def expire(self, anchor: str, at: datetime) -> None: ...  # expiry set to now and credential disabled, same step
    def events(self) -> list[dict]: ...                    # granted, denied, entry, exit since the last call


def plan(want: dict, state: dict, at: datetime) -> dict:
    create, update, expire, findings = [], [], [], []
    for anchor, w in sorted(want.items()):
        have = state.get(anchor)
        if have is None:
            create.append(anchor)
        elif any(have.get(k) != w[k] for k in ("credential", "levels", "activation", "expiry")):
            update.append(anchor)
    for anchor, have in sorted(state.items()):
        if have.get("source") != SOURCE:
            continue   # not ours: the PACS's own cardholders are never touched
        if anchor in want:
            continue
        if have.get("expiry") and have["expiry"] <= at:
            continue   # already expired at the door
        expire.append(anchor)
        if not have.get("lease_id"):
            findings.append({"anchor": anchor, "why": "undeclared credential in the PACS under our management"})
    return {"at": at.isoformat(), "create": create, "update": update, "expire": expire, "findings": findings}


def apply(conn: PacsConnector, want: dict, p: dict, at: datetime) -> None:
    for anchor in p["create"] + p["update"]:
        conn.upsert(anchor, dict(want[anchor], source=SOURCE))
    for anchor in p["expire"]:
        conn.expire(anchor, at)


@dataclass
class SimulatedPacs:
    """A PACS head-end with its field controllers, for CI: it keeps the cardholders with their dates and decides at the
    door on its own data, so cutting the IT link (no more upserts) changes nothing at the door."""
    holders: dict = field(default_factory=dict)
    log: list = field(default_factory=list)
    foreign: dict = field(default_factory=dict)   # the PACS's own cardholders, not managed by us

    def cardholders(self) -> dict:
        return {**self.foreign, **{a: dict(h) for a, h in self.holders.items()}}

    def upsert(self, anchor: str, holder: dict) -> None:
        self.holders[anchor] = dict(holder)

    def expire(self, anchor: str, at: datetime) -> None:
        h = self.holders.get(anchor)
        if h is not None:
            h["expiry"] = at
            h["disabled"] = True

    def badge_read(self, badge: str, site: str, area: str | None, at: datetime) -> Decision:
        for anchor, h in self.holders.items():
            if h["credential"] != badge:
                continue
            rec = BadgeRecord(badge, h.get("lease_id", ""), anchor, frozenset(x.split(":")[0] for x in h["levels"]),
                              frozenset(x.split(":")[1] for x in h["levels"] if ":" in x), h["activation"], h["expiry"])
            d = Allowlist([rec], set()).decide(badge, site, area or "", at)
            if h.get("disabled"):
                d = Decision(False, "credential-disabled", rec)
            self.log.append({"anchor": anchor, "site": site, "granted": d.granted, "reason": d.reason, "at": at})
            return d
        self.log.append({"anchor": None, "site": site, "granted": False, "reason": "unknown-badge", "at": at})
        return Decision(False, "unknown-badge")

    def events(self) -> list[dict]:
        out, self.log = self.log, []
        return out
