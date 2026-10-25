# SPDX-License-Identifier: EUPL-1.2
"""Shared core of physical access: badge records, the decision on a card read, the roll call and events.

A badge record belongs to one lease: the badge id is never stored, only a keyed hash (HMAC-SHA256 with the site's
badge key, which lives in OpenBao, never in git). The record carries the lease's start and end and the sites and areas
the lease reaches. A card read is granted only for a known badge, inside its window, on a site and area it names, and
for a lease that is not revoked; everything else is denied with a reason.

OCSF has no physical-access class that we found (UNVERIFIED against the newest OCSF release), so a card read is shaped
as Authentication (class_uid 3002): entry is a logon (activity 1), exit a logoff (activity 2), a denial a logon with
status failure; the door, reader and site go under unmapped.keyclerk.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone


def badge_hash(key: bytes, raw: bytes) -> str:
    """Keyed hash of a badge id as read from the card; the only form in which a badge id is kept."""
    return "hmac-sha256:" + hmac.new(key, raw, hashlib.sha256).hexdigest()


def _ts(v) -> datetime:
    d = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class BadgeRecord:
    badge: str            # keyed hash, never the raw id
    lease_id: str
    anchor: str
    sites: frozenset
    areas: frozenset      # empty means every area of the named sites
    start: datetime
    end: datetime


def records_from_leases(leases: list[dict], physical: list[dict]) -> list[BadgeRecord]:
    """leases: the lease records (lease_id, anchor, start, end); physical: per lease the badge hash, sites and areas.
    The record's window is the lease's: a badge never outlives its lease."""
    by_id = {x["lease_id"]: x for x in leases}
    out = []
    for p in physical:
        lease = by_id.get(p["lease_id"])
        if lease is None:
            continue   # a badge without a lease is never on the allowlist
        out.append(BadgeRecord(p["badge"], lease["lease_id"], lease["anchor"], frozenset(p["sites"]),
                               frozenset(p.get("areas", [])), _ts(lease["start"]), _ts(lease["end"])))
    return out


@dataclass(frozen=True)
class Decision:
    granted: bool
    reason: str
    record: BadgeRecord | None = None


class Allowlist:
    def __init__(self, records: list[BadgeRecord], revoked_leases: set[str] | frozenset = frozenset()):
        self.by_badge = {r.badge: r for r in records}
        self.revoked = set(revoked_leases)

    def decide(self, badge: str, site: str, area: str, at: datetime) -> Decision:
        r = self.by_badge.get(badge)
        if r is None:
            return Decision(False, "unknown-badge")
        if r.lease_id in self.revoked:
            return Decision(False, "lease-revoked", r)
        if at < r.start:
            return Decision(False, "not-yet-valid", r)
        if at >= r.end:
            return Decision(False, "lease-ended", r)
        if site not in r.sites:
            return Decision(False, "outside-site", r)
        if r.areas and area not in r.areas:
            return Decision(False, "outside-area", r)
        return Decision(True, "granted", r)


@dataclass
class RollCall:
    """Who is in, per site, from entry and exit events; the evacuation list."""
    inside: dict = field(default_factory=dict)   # site -> {anchor: since}

    def record(self, site: str, anchor: str, direction: str, at: datetime) -> None:
        here = self.inside.setdefault(site, {})
        if direction == "entry":
            here[anchor] = at
        else:
            here.pop(anchor, None)

    def end_lease(self, anchor: str) -> list[str]:
        """A lease that ends while its holder is inside: the person stays on the roll call (they are still physically
        there) and the sites are returned so the desk is told."""
        return sorted(s for s, people in self.inside.items() if anchor in people)

    def on_site(self, site: str) -> list[str]:
        return sorted(self.inside.get(site, {}))


def ocsf_event(decision: Decision, site: str, door: str, reader: int, direction: str, at: datetime) -> dict:
    entry = direction == "entry"
    return {
        "class_uid": 3002, "category_uid": 3, "class_name": "Authentication",
        "activity_id": 1 if entry or not decision.granted else 2,
        "status": "Success" if decision.granted else "Failure",
        "status_detail": decision.reason,
        "time": int(at.timestamp() * 1000),
        "user": {"uid": decision.record.anchor} if decision.record else {},
        "auth_protocol": "badge",
        "unmapped": {"keyclerk": {"site": site, "door": door, "reader": reader, "direction": direction,
                             "lease_id": decision.record.lease_id if decision.record else None}},
    }
