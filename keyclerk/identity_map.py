# SPDX-License-Identifier: EUPL-1.2
"""The sealed identity map (0021 point 2): per anchor, the broker's username and verified e-mail, sealed by the
reconciler with its own key (the key of its high-water mark), so the checking signer can refuse a lease that names
anyone else's account or address.

The reconciler reads both from the broker at each run. A taken-over desk could otherwise write any username or e-mail
into a lease, and Warpgate signs a single sign-on login in by e-mail. The map is bound to the realm and ordered by its
time: a map older than one already accepted is refused, so an old map cannot be replayed to bring a changed address
back.
"""
from __future__ import annotations

from datetime import datetime, timezone

FORMAT = "kc-identity-map-v1"
MAX_PEOPLE = 200_000


def seal(key, realm: str, revision: int | None, at: datetime, usernames: dict, emails: dict) -> dict:
    """The map as the reconciler seals it: revision is the records revision its run applied (None before one)."""
    from keyclerk import edge as E
    people = {}
    for anchor in sorted(set(usernames) | set(emails)):
        people[str(anchor)] = {"username": usernames.get(anchor), "email": emails.get(anchor)}
    return E.seal(key, {"realm": realm, "revision": revision, "at": E._iso(at.astimezone(timezone.utc)),
                        "people": people}, FORMAT)


def open_map(sealed, pinned_hex: str, realm: str, not_before: str | None = None) -> dict:
    """What a sealed map says, or ValueError: the pinned key, this realm, well-formed people, and not older than
    not_before (the time of the newest map already accepted)."""
    from keyclerk import edge as E
    m = E.unseal(sealed, pinned_hex, FORMAT)
    if m.get("realm") != realm:
        raise ValueError(f"an identity map for realm {m.get('realm')!r}, not {realm!r}")
    at = m.get("at")
    try:
        E._ts(at)
    except (ValueError, TypeError):
        raise ValueError("an identity map without a valid time") from None
    if not_before is not None and E._ts(at) < E._ts(not_before):
        raise ValueError(f"an identity map of {at}, older than the one already accepted ({not_before}): a replay")
    rev = m.get("revision")
    if rev is not None and (not isinstance(rev, int) or isinstance(rev, bool) or rev < 0):
        raise ValueError("an identity map's revision is a whole number or null")
    people = m.get("people")
    if not isinstance(people, dict) or len(people) > MAX_PEOPLE:
        raise ValueError(f"an identity map's people are an object of at most {MAX_PEOPLE}")
    for anchor, p in people.items():
        if not isinstance(p, dict) or set(p) != {"username", "email"} or not all(
                v is None or (isinstance(v, str) and 0 < len(v) <= 320) for v in p.values()):
            raise ValueError(f"an identity map entry for {anchor[:80]!r} is exactly {{username, email}}, each text or null")
    return m


def usernames(m: dict) -> dict:
    return {a: p["username"] for a, p in m["people"].items() if p.get("username")}


def emails(m: dict) -> dict:
    return {a: p["email"] for a, p in m["people"].items() if p.get("email")}


def at_of(m: dict) -> datetime:
    from keyclerk import edge as E
    return E._ts(m["at"])
