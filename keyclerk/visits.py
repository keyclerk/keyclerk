# SPDX-License-Identifier: EUPL-1.2
"""Visits (decisions 0009 and 0010): who comes, when, how, with what, and what happened on the day, person by person.

A visit is the meeting or event, and the only thing that admits someone on site: the place, the window and the margins
around it (fixed when it is registered), the purpose, the host (someone of the tenant who receives the guests), the
organiser, the escorts (internal staff who accompany guests that may not walk unescorted), the zones asked for, and an
optional delegation (the group the attendees belong to).

The person is the unit (0010). Each attendee has a registration state: `registered` (a person record, self-registered
beforehand), `invited` (expected by name, not registered yet), `registered-on-site` (registered at the front office on
arrival), or `unregistered` (a label and no identity: never more than an escorted visitor badge). Each has an expected
arrival, an escort, kit by class, their own code, badges and gate history. People added on the day and people registered
at the front office are events, so the records stay append-only.

People arrive on foot or in a vehicle, together or apart. Vehicles announced beforehand are listed on the visit (the
plate only as a keyed digest and its last three characters); an arrival names the vehicle it came in, or a plate typed
at the gate. A vehicle comes in only with a registered driver.

What happens on the day is a visit event, append-only: attendee-added, registered-on-site, arrived (a person's first
entry, which notifies the host and organiser), entered, acknowledged, confirmed, reminded, suspended (flagged for the
officer), left, qr-issued, badge-returned.

keyclerk/policy/visits.rego decides who may act, entry at a checkpoint, which timers are due, who may see a visit, the
phone scan and badges, compiled in like every rule; this module gathers the facts and checks the records. Visits made
by 0.10.0 to 0.12.0 (`parties`, one driver or lead) are read as they are.

Records:
  visits        {visit_id, place, host, organiser, escorts?, purpose, start, end, opens, closes, zones?, delegation?,
                 attendees, vehicles?, by, at}
                 attendee: {party, state, anchor?, name?, label?, organisation?, expected?, escort?, kit?}
                 vehicle:  {vehicle, plate_digest, plate_tail, make?, model?, colour?, driver?}
  visit_events  {event_id, visit_id, party?, kind, at, by, checkpoint?, zone?, presented?, vehicle?, vehicle_id?,
                 vehicle_digest?, vehicle_tail?, notify?, reason?, qr?, serial?, badge?, attendee?, anchor?}
  badges        {badge_id, visit_id, party, kind: visitor | restricted, badge_digest, badge_tail, issued_by,
                 approved_by, from, to}: the badge number only as a keyed digest; a RESTRICTED badge carries the second
                 key in approved_by; returning one is a badge-returned visit event
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta

from keyclerk import config
from keyclerk.grants import _ts

DEFAULTS = {"early_minutes": 120, "late_minutes": 120, "confirm_after_minutes": 15, "grace_minutes": 5,
            "max_visit_hours": 14, "max_parties": 60, "qr_required": True, "scan_per_minute": 30,
            "badges_required": True, "retention_days": 30,
            "kit_classes": [{"class": "it-device", "name": "IT device"}, {"class": "tool", "name": "Tool"},
                            {"class": "goods", "name": "Compliant goods"}, {"class": "documents", "name": "Documents"},
                            {"class": "media", "name": "Removable media"}, {"class": "bag", "name": "Bag"}]}
STATES = ("registered", "invited", "registered-on-site", "unregistered")
KINDS = ("arrived", "entered", "acknowledged", "confirmed", "reminded", "suspended", "left", "qr-issued",
         "badge-returned", "attendee-added", "registered-on-site")
BADGES = ("visitor", "restricted")
PRESENTED = ("qr", "visitor-badge", "restricted-badge", "none")
TIMER = "keyclerk:timer"                  # the engine's own schedule, as the actor of timer steps
DIGEST = re.compile(r"hmac-sha256:[0-9a-f]{64}")
LEGACY_ROLES = ("driver", "lead", "passenger")


def rules() -> dict:
    """The visits section of the configuration, over the defaults (a deployment without one gets these)."""
    return {**DEFAULTS, **(config.current().get("visits") or {})}


def plate_digest(key: bytes, plate: str) -> tuple[str, str]:
    """(keyed digest, last three characters) of a plate or a badge number; spaces, dots and dashes do not count."""
    norm = re.sub(r"[\s\-.]", "", plate).upper()
    if not 2 <= len(norm) <= 12 or not norm.isalnum():
        raise ValueError("2 to 12 letters and digits")
    return "hmac-sha256:" + hmac.new(key, norm.encode(), hashlib.sha256).hexdigest(), norm[-3:]


def _epoch(t) -> int:
    return int(_ts(t).timestamp())


def window(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    r = rules()
    return start - timedelta(minutes=r["early_minutes"]), end + timedelta(minutes=r["late_minutes"])


_INDEX: dict[int, tuple[int, list, dict]] = {}


def _by_visit(doc: dict, kind: str) -> dict[str, list[dict]]:
    """The records of one kind grouped by visit id, built once per list (a check looks at every party of every visit:
    scanning all events each time made it quadratic in the visits kept). Keyed on the list itself and its
    length, holding the list so its id is not reused."""
    lst = doc.get(kind) or []
    hit = _INDEX.get(id(lst))
    if hit is not None and hit[1] is lst and hit[0] == len(lst):
        return hit[2]
    idx: dict[str, list[dict]] = {}
    for r in lst:
        idx.setdefault(r.get("visit_id"), []).append(r)
    if len(_INDEX) > 32:
        _INDEX.clear()
    _INDEX[id(lst)] = (len(lst), lst, idx)
    return idx


def visit(doc: dict, vid: str) -> dict | None:
    return next(iter(_by_visit(doc, "visits").get(vid, [])), None)


def events(doc: dict, vid: str, at: datetime | None = None) -> list[dict]:
    evs = [e for e in _by_visit(doc, "visit_events").get(vid, []) if at is None or _ts(e["at"]) <= at]
    return sorted(evs, key=lambda e: (_ts(e["at"]), e["event_id"]))


def _legacy(v: dict) -> list[dict]:
    """Attendees of a visit made by 0.10.0 to 0.12.0 (parties with roles, kit on the visit)."""
    out = []
    for p in v.get("parties") or []:
        a = {"party": p["party"], "state": "registered" if "anchor" in p else "unregistered"}
        if "anchor" in p:
            a["anchor"] = p["anchor"]
        if p.get("label"):
            a["label"] = p["label"]
        kit = [{k: i[k] for k in ("class", "count", "note") if k in i} for i in v.get("kit") or [] if i.get("with") == p["party"]]
        if kit:
            a["kit"] = kit
        out.append(a)
    return out


def attendees(doc: dict, v: dict, at: datetime | None = None) -> list[dict]:
    """Everyone on the visit by `at`: as registered, plus people added on the day and registrations at the front
    office."""
    out = [dict(a) for a in (v.get("attendees") or _legacy(v))]
    for e in events(doc, v["visit_id"], at):
        if e["kind"] == "attendee-added" and isinstance(e.get("attendee"), dict):
            out.append({**e["attendee"], "party": e["party"]})
        elif e["kind"] == "registered-on-site":
            for a in out:
                if a["party"] == e.get("party"):
                    a["state"], a["anchor"] = "registered-on-site", e["anchor"]
    return out


def party(doc: dict, v: dict, pid: str, at: datetime | None = None) -> dict | None:
    return next((a for a in attendees(doc, v, at) if a["party"] == pid), None)


def registered(a: dict | None) -> bool:
    return bool(a) and "anchor" in a


def next_party(doc: dict, v: dict) -> str:
    used = [int(a["party"][1:]) for a in attendees(doc, v) if re.fullmatch(r"P\d+", a["party"])]
    return f"P{max(used, default=0) + 1}"


def vehicles(v: dict) -> list[dict]:
    return list(v.get("vehicles") or [])


def escorts_of(v: dict) -> list[str]:
    return list(v.get("escorts") or [])


def state(doc: dict, v: dict, pid: str, at: datetime) -> dict:
    """What has happened to one person by `at`."""
    evs = [e for e in events(doc, v["visit_id"], at) if e.get("party") == pid]
    first = next((e for e in evs if e["kind"] == "arrived"), None)
    kinds = {e["kind"] for e in evs}
    return {"arrived": _ts(first["at"]) if first else None, "acknowledged": "acknowledged" in kinds,
            "confirmed": "confirmed" in kinds, "reminded": "reminded" in kinds, "suspended": "suspended" in kinds,
            "departed": "left" in kinds}


def qr_serial(doc: dict, v: dict, pid: str, at: datetime | None = None) -> int:
    """The serial of the latest QR code issued for a person (0: none); only that one is current."""
    return max((e.get("serial", 0) for e in events(doc, v["visit_id"], at)
                if e.get("party") == pid and e["kind"] == "qr-issued"), default=0)


def badges_of(doc: dict, vid: str, pid: str | None = None) -> list[dict]:
    return [b for b in _by_visit(doc, "badges").get(vid, []) if pid is None or b["party"] == pid]


def returned(doc: dict, b: dict, at: datetime | None = None) -> datetime | None:
    e = next((e for e in events(doc, b["visit_id"], at) if e["kind"] == "badge-returned" and e.get("badge") == b["badge_id"]), None)
    return _ts(e["at"]) if e else None


def badges_held(doc: dict, v: dict, pid: str, at: datetime) -> dict:
    """Which badge kinds this person holds at `at`: issued, inside its window, not returned."""
    held = {"visitor": False, "restricted": False}
    for b in badges_of(doc, v["visit_id"], pid):
        if _ts(b["from"]) <= at < _ts(b["to"]) and returned(doc, b, at) is None:
            held[b["kind"]] = True
    return held


def ended(v: dict, at: datetime) -> bool:
    return at >= _ts(v["closes"])


def entry_input(doc: dict, v: dict, pid: str, at: datetime, zone: str | None, presented: str, vehicle: bool,
                qr: dict | None = None) -> dict:
    a, st = party(doc, v, pid, at), state(doc, v, pid, at)
    z = next((x for x in doc.get("zones", []) if x["zone_id"] == zone), None) if zone else None
    return {"now": _epoch(at), "visit": {"opens": _epoch(v["opens"]), "closes": _epoch(v["closes"]), "ended": ended(v, at)},
            "party": {"registered": registered(a), "suspended": st["suspended"], "departed": st["departed"]},
            "zone": {"zone_id": z["zone_id"], "badge": z.get("badge")} if z else None,
            "presented": presented, "vehicle": bool(vehicle),
            "qr": qr or {"required": bool(rules()["qr_required"]), "valid": False, "problem": "no code was presented"},
            "badges": {"required": bool(rules()["badges_required"]), **badges_held(doc, v, pid, at)}}


def timer_input(doc: dict, at: datetime) -> dict:
    r = rules()
    parties = []
    for v in doc.get("visits", []):
        if not (_ts(v["opens"]) <= at < _ts(v["closes"])):
            continue
        for a in attendees(doc, v, at):
            st = state(doc, v, a["party"], at)
            if st["arrived"] is not None:
                parties.append({"visit_id": v["visit_id"], "party": a["party"], "arrived": int(st["arrived"].timestamp()),
                                "acknowledged": st["acknowledged"], "confirmed": st["confirmed"], "reminded": st["reminded"],
                                "departed": st["departed"], "suspended": st["suspended"], "closes": _epoch(v["closes"])})
    return {"now": _epoch(at), "confirm_after": 60 * r["confirm_after_minutes"], "grace": 60 * r["grace_minutes"],
            "parties": parties}


def timeline(doc: dict, v: dict, at: datetime) -> list[dict]:
    """The visit's moments up to `at`, and the ones still ahead of it: the window, who is expected when, what happened,
    and the timer steps a person will meet if nothing changes (each re-checks its reason when it fires)."""
    r = rules()
    out = [{"at": v["opens"], "kind": "opens", "text": "the visit opens (entry allowed from now)"},
           {"at": v["start"], "kind": "start", "text": "the meeting starts"},
           {"at": v["end"], "kind": "end", "text": "the meeting ends"},
           {"at": v["closes"], "kind": "closes", "text": "the visit closes (everyone out)"}]
    out += [{**e, "text": e.get("reason") or e["kind"]} for e in events(doc, v["visit_id"], at)]
    for a in attendees(doc, v, at):
        st = state(doc, v, a["party"], at)
        if a.get("expected") and st["arrived"] is None:
            out.append({"at": a["expected"], "kind": "expected", "party": a["party"], "text": "expected"})
        if st["arrived"] is None or st["confirmed"] or st["departed"] or st["suspended"]:
            continue
        rem = st["arrived"] + timedelta(minutes=r["confirm_after_minutes"])
        sus = rem + timedelta(minutes=r["grace_minutes"])
        if not st["reminded"]:
            out.append({"at": rem, "kind": "remind-due", "party": a["party"], "text": "the host is reminded to confirm"})
        out.append({"at": sus, "kind": "suspend-due", "party": a["party"],
                    "text": "access is suspended and flagged unless the host confirms before"})
    return sorted(out, key=lambda x: _ts(x["at"]))


def place_staff(doc: dict, place: str, anchor: str | None) -> tuple[bool, bool]:
    """(front office, steward or deputy) of this place or a place containing it."""
    from keyclerk import delegation as D
    if not anchor:
        return False, False
    byid = {p["place_id"]: p for p in doc.get("places", [])}
    fo = st = False
    seen, pid = set(), place
    while pid in byid and pid not in seen:
        seen.add(pid)
        pl = byid[pid]
        fo = fo or any(D.same(doc, anchor, x) for x in pl.get("front_office") or [])
        st = st or any(D.same(doc, anchor, x) for x in (pl.get("steward"), pl.get("deputy")) if x)
        pid = pl.get("within")
    return fo, st


def badge_input(doc: dict, v: dict, b: dict) -> dict:
    """The facts visits.rego (badge) judges a badge on, as made: at its `from`."""
    from keyclerk import delegation as D
    at = _ts(b["from"])
    a, st = party(doc, v, b["party"], at), state(doc, v, b["party"], at)
    fo, sw = place_staff(doc, v["place"], b["issued_by"])
    seconds = []
    for x in b.get("approved_by") or []:
        f2, s2 = place_staff(doc, v["place"], x)
        seconds.append({"front_office": f2, "steward": s2, "is_issuer": D.same(doc, x, b["issued_by"])})
    return {"badge": {"kind": b["kind"], "from": _epoch(b["from"]), "to": _epoch(b["to"])},
            "visit": {"opens": _epoch(v["opens"]), "closes": _epoch(v["closes"])},
            "party": {"registered": registered(a), "suspended": st["suspended"], "departed": st["departed"]},
            "issuer": {"front_office": fo, "steward": sw}, "seconds": seconds}


def _persons(doc: dict) -> dict:
    return {a: p for p in doc.get("persons", []) for a in p["anchors"]}


def attendee_errors(where: str, a: dict, persons: dict, kit: set, v: dict) -> list[str]:
    """What makes one attendee wrong: its state and identity, escort, expected arrival and kit."""
    errs = []
    st = a.get("state")
    if st not in STATES or st == "registered-on-site":
        errs.append(f"{where}: state is registered, invited or unregistered (registered-on-site comes from the front office)")
    elif st == "registered" and a.get("anchor") not in persons:
        errs.append(f"{where}: a registered attendee is a person in the records")
    elif st == "invited" and ("anchor" in a or not a.get("name")):
        errs.append(f"{where}: an invited attendee is expected by name, without an identity yet")
    elif st == "unregistered" and ("anchor" in a or not a.get("label")):
        errs.append(f"{where}: an unregistered attendee has a label and no identity")
    if a.get("escort") and a["escort"] not in persons:
        errs.append(f"{where}: the escort is not in the persons")
    if a.get("expected") and not _ts(v["opens"]) <= _ts(a["expected"]) < _ts(v["closes"]):
        errs.append(f"{where}: expected inside the visit window")
    for i in a.get("kit") or []:
        if i.get("class") not in kit or not isinstance(i.get("count"), int) or not 1 <= i["count"] <= 50:
            errs.append(f"{where}: kit is a class from {', '.join(sorted(kit))} and a count from 1 to 50")
    return errs


def check(doc: dict) -> list[str]:
    """What makes visit records wrong whatever the policy says: references, windows, attendees, vehicles and kit."""
    r, errs = rules(), []
    persons = _persons(doc)
    places = {p["place_id"] for p in doc.get("places", [])}
    zones = {z["zone_id"] for z in doc.get("zones", [])}
    kit = {k["class"] for k in r["kit_classes"]}
    seen = {}
    for v in doc.get("visits", []):
        vid = v["visit_id"]
        if v["place"] not in places:
            errs.append(f"{vid}: unknown place {v['place']}")
        for f in ("host", "organiser", "by"):
            if v[f] not in persons:
                errs.append(f"{vid}: {f} {v[f]} is not in the persons")
        for x in escorts_of(v):
            if x not in persons:
                errs.append(f"{vid}: escort {x} is not in the persons")
        start, end, opens, closes = (_ts(v[k]) for k in ("start", "end", "opens", "closes"))
        if not opens <= start < end <= closes:
            errs.append(f"{vid}: the window must run opens <= start < end <= closes")
        if end - start > timedelta(hours=r["max_visit_hours"]):
            errs.append(f"{vid}: a visit lasts at most {r['max_visit_hours']} hours")
        if start - opens > timedelta(minutes=r["early_minutes"]) or closes - end > timedelta(minutes=r["late_minutes"]):
            errs.append(f"{vid}: the margins are wider than the policy allows")
        for z in v.get("zones") or []:
            if z not in zones:
                errs.append(f"{vid}: unknown zone {z}")
        if "attendees" in v:
            ps = v["attendees"]
            for a in ps:
                errs += attendee_errors(f"{vid}/{a.get('party')}", a, persons, kit, v)
        else:                                          # made by 0.10.0 to 0.12.0
            ps = v.get("parties") or []
            if sum(p.get("role") in ("driver", "lead") for p in ps) != 1:
                errs.append(f"{vid}: exactly one driver or lead")
            for p in ps:
                if p.get("role") not in LEGACY_ROLES or ("anchor" in p and p["anchor"] not in persons):
                    errs.append(f"{vid}/{p.get('party')}: a role and, when registered, a person in the records")
        ids = [a["party"] for a in ps]
        if not 1 <= len(ps) <= r["max_parties"] or len(set(ids)) != len(ids):
            errs.append(f"{vid}: 1 to {r['max_parties']} attendees, each with its own id")
        for k in vehicles(v):
            if k.get("driver") is not None and not registered(next((a for a in attendees({}, v) if a["party"] == k["driver"]), None)):
                errs.append(f"{vid}/{k['vehicle']}: a vehicle's driver is a registered attendee")
            if not DIGEST.fullmatch(k["plate_digest"]):
                errs.append(f"{vid}/{k['vehicle']}: the plate is kept only as a keyed digest")
        seen[vid] = v
    from keyclerk import policy_wasm
    for b in doc.get("badges", []):
        v = seen.get(b["visit_id"])
        if v is None or party(doc, v, b["party"], _ts(b["from"])) is None:
            errs.append(f"{b['badge_id']}: names no attendee of a known visit")
            continue
        if b["kind"] not in BADGES or not DIGEST.fullmatch(b["badge_digest"]):
            errs.append(f"{b['badge_id']}: kind visitor or restricted, the number only as a keyed digest")
            continue
        errs += [f"{b['badge_id']}: {x}" for x in policy_wasm.visits("badge", badge_input(doc, v, b))]
    for e in sorted(doc.get("visit_events", []), key=lambda e: (_ts(e["at"]), e["event_id"])):
        v = seen.get(e["visit_id"])
        if v is None:
            errs.append(f"{e['event_id']}: unknown visit {e['visit_id']}")
            continue
        if e["kind"] not in KINDS:
            errs.append(f"{e['event_id']}: kind is one of {', '.join(KINDS)}")
        before = {a["party"]: a for a in attendees(doc, v, _ts(e["at"]) - timedelta(microseconds=1))}
        if e["kind"] == "attendee-added":
            if not isinstance(e.get("attendee"), dict) or e.get("party") in before or "party" in e["attendee"]:
                errs.append(f"{e['event_id']}: adds a new attendee under a new id")
            else:
                errs += attendee_errors(e["event_id"], e["attendee"], persons, kit, v)
        elif e["kind"] == "registered-on-site":
            if e.get("party") not in before or registered(before[e["party"]]) or e.get("anchor") not in persons:
                errs.append(f"{e['event_id']}: registers an attendee without an identity as a person in the records")
        elif e.get("party") is not None and party(doc, v, e["party"], _ts(e["at"])) is None:
            errs.append(f"{e['event_id']}: {e['party']} is not an attendee of {e['visit_id']}")
        if e["by"] != TIMER and e["by"] not in persons:
            errs.append(f"{e['event_id']}: by {e['by']} is not in the persons")
        if e.get("presented") is not None and e["presented"] not in PRESENTED:
            errs.append(f"{e['event_id']}: presented is one of {', '.join(PRESENTED)}")
        if e.get("vehicle_digest") is not None and not DIGEST.fullmatch(e["vehicle_digest"]):
            errs.append(f"{e['event_id']}: a plate typed at the gate is kept only as a keyed digest")
        if e.get("vehicle_id") is not None and not any(k["vehicle"] == e["vehicle_id"] for k in vehicles(v)):
            errs.append(f"{e['event_id']}: names no announced vehicle of {e['visit_id']}")
        if e["kind"] == "badge-returned" and not any(b["badge_id"] == e.get("badge") and b["visit_id"] == e["visit_id"]
                                                     for b in doc.get("badges", [])):
            errs.append(f"{e['event_id']}: returns no badge of {e['visit_id']}")
        if e["kind"] == "qr-issued":
            a = party(doc, v, e.get("party") or "", _ts(e["at"]))
            if not registered(a) or not isinstance(e.get("serial"), int) or e["serial"] < 1 \
                    or not str(e.get("qr", "")).startswith("sha256:"):
                errs.append(f"{e['event_id']}: a QR code is issued to a registered attendee, with a serial and a digest")
    return errs
