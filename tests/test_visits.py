# SPDX-License-Identifier: EUPL-1.2
"""Visits (decision 0009): the worked example. A driver comes in a black Toyota RAV4 with two laptops, a backpack and
one unregistered passenger, for a meeting from 13:00 to 14:00 with two hours either side. The driver passes with the
QR and the vehicle; the passenger waits for a temporary visitor badge; a Restricted zone needs a RESTRICTED badge,
which the passenger can never get; the host and organiser are notified, and without their confirmation the timers
remind and then suspend, each re-checking its reason. Every decision is visits.rego, compiled in."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import records
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
ANN, EVA, CARLA, GUARD, DIRK = "idp:7c1f-ann", "idp:55bb-eva", "ext:3a71-carla", "idp:ee01-guard", "idp:44aa-dirk"
VIEWER = {"anchor": None, "roles": ["keyclerk-viewer"]}
LAB = "zone:heverlee-lab"


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def at(self, hhmm: str, day: int = 26):
        h, m = map(int, hhmm.split(":"))
        self.t = datetime(2026, 10, day, h, m, tzinfo=timezone.utc)


@pytest.fixture(params=["yaml", "sqlite"])
def desk(request, tmp_path):
    """The visit desk on both stores (decision 0022 S5)."""
    d = visit_desk(tmp_path, request.param)
    yield d
    d.store.close()
    if getattr(d, "test_signer", None):
        d.test_signer.close()


def visit_desk(tmp_path, kind="yaml"):
    doc = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    for pl in doc["places"]:
        if pl["place_id"] == "place:heverlee":
            pl["front_office"] = [GUARD]
    doc.setdefault("zones", []).append({"zone_id": LAB, "kind": "security", "members": ["place:heverlee/depot"],
                                        "badge": "restricted"})
    seed = tmp_path / "seed.yaml"
    seed.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    clock = Clock(datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc))
    if kind == "sqlite":
        from keyclerk.signer import Signer
        from keyclerk.store.log_desk import LogStore
        signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
        d = Desk(LogStore(tmp_path / "store", signer, seed), clock=clock)
        d.test_signer = signer
    else:
        d = Desk(Store(tmp_path / "store", key, seed), clock=clock)
    d.test_clock = clock
    return d


def as_held(desk, *names):
    """Names as the store's records hold them (decision 0028): internal anchors on the change log, as given on YAML."""
    out = [desk.store.inward(n) or n for n in names]
    return out[0] if len(out) == 1 else out


def signed_text(desk) -> str:
    """Everything the store keeps signed for good: the published records, or every link of the change log."""
    if hasattr(desk.store, "follower"):
        return json.dumps(list(desk.store.store.links()))
    return (desk.store.path / "records.yaml").read_text(encoding="utf-8")


def register(desk, who=ANN):
    return desk.propose(W(who), {
        "action": "register_visit", "place": "place:heverlee", "host": ANN, "organiser": EVA, "purpose": "supplier meeting",
        "start": "2026-10-26T13:00:00Z", "end": "2026-10-26T14:00:00Z", "zones": [LAB],
        "attendees": [{"anchor": CARLA, "kit": [{"class": "it-device", "count": 2}, {"class": "bag", "count": 1, "note": "backpack"}]},
                      {"unregistered": True, "label": "passenger"}],
        "vehicles": [{"plate": "2-XXX-111", "make": "Toyota", "model": "RAV4", "colour": "black", "driver": 1}]})


def code(desk, party="P1"):
    return desk.visit_qr(W(CARLA), "V-example-0001", party)["token"]


BERT = "idp:91d0-bert"                                     # the deputy of Heverlee: a steward, so a second key


def badge(desk, party, kind="visitor", number="VB-0042"):
    """The front office hands a badge out; a RESTRICTED one waits for a second key, which bert gives."""
    from keyclerk import visits as V
    doc = desk.store.load()
    v = V.visit(doc, "V-example-0001")
    if V.badges_held(doc, v, party, desk.test_clock())[kind]:
        return None
    r = desk.propose(W(GUARD), {"action": "issue_badge", "visit_id": "V-example-0001", "party": party, "kind": kind,
                                "badge": number})
    if r["outcome"] == "pending":
        r = desk.approve(W(BERT), r["change_id"])
    return r


def entry(desk, party, presented, vehicle=False, zone=None):
    body = {"action": "record_entry", "visit_id": "V-example-0001", "party": party, "presented": presented,
            "vehicle": vehicle, "checkpoint": "main gate"}
    if presented == "qr":                                 # the guard scans the guest's code
        body["token"] = code(desk, party)
    if presented.endswith("-badge"):                      # the badge was handed out first
        badge(desk, party, presented.removesuffix("-badge"), "RB-0007" if presented.startswith("restricted") else "VB-0042")
    if zone:
        body["zone"] = zone
    return desk.propose(W(GUARD), body)


def test_registering_keeps_the_window_and_never_the_plate(desk):
    r = register(desk)
    assert r["outcome"] == "applied"
    v = r["records"]["visits"][0]
    assert v["opens"].startswith("2026-10-26T11:00") and v["closes"].startswith("2026-10-26T16:00")
    assert v["vehicles"][0]["plate_tail"] == "111" and v["vehicles"][0]["plate_digest"].startswith("hmac-sha256:")
    stored = "".join(f.read_text(encoding="utf-8", errors="replace") for f in desk.store.path.rglob("*")
                     if f.is_file() and f.suffix in (".yaml", ".jsonl", ".json", ".log"))
    assert "2-XXX-111" not in stored and "2XXX111" not in stored
    with pytest.raises(Refusal):                         # only the host or the organiser registers a visit
        register(desk, who=GUARD)


def test_the_example_at_the_gate(desk):
    register(desk)
    c = desk.test_clock
    c.at("10:59")
    with pytest.raises(Refusal, match="too early"):
        entry(desk, "P1", "qr", vehicle=True)
    c.at("11:05")
    r = entry(desk, "P1", "qr", vehicle=True)              # the driver and the vehicle pass on the QR
    ev = r["records"]["visit_events"][0]
    assert ev["kind"] == "arrived" and set(ev["notify"]) == set(as_held(desk, ANN, EVA))
    with pytest.raises(Refusal, match="front office for a temporary visitor badge") as e:
        entry(desk, "P2", "none")                          # the unregistered passenger waits in line
    assert e.value.next and "visitor badge" in e.value.next[0]["do"]
    with pytest.raises(Refusal, match="registered driver"):
        entry(desk, "P2", "visitor-badge", vehicle=True)
    assert entry(desk, "P2", "visitor-badge")["records"]["visit_events"][0]["reason"].startswith("escorted")
    with pytest.raises(Refusal, match="RESTRICTED badge") as e:   # the Restricted zone: the driver to the front office
        entry(desk, "P1", "qr", zone=LAB)
    assert "restricted badge" in e.value.next[0]["do"]
    assert entry(desk, "P1", "restricted-badge", zone=LAB)["outcome"] == "applied"
    with pytest.raises(Refusal, match="never"):            # the passenger can never get one
        entry(desk, "P2", "visitor-badge", zone=LAB)
    r = desk.propose(W(GUARD), {"action": "issue_badge", "visit_id": "V-example-0001", "party": "P2", "kind": "restricted",
                                "badge": "RB-0008"})
    assert r["outcome"] == "refused" and any("never receive a RESTRICTED badge" in x for x in r["reasons"])


def test_unconfirmed_guests_are_reminded_then_suspended_and_flagged(desk):
    register(desk)
    c = desk.test_clock
    c.at("11:05")
    entry(desk, "P1", "qr", vehicle=True)
    desk.propose(W(ANN), {"action": "acknowledge_arrival", "visit_id": "V-example-0001", "party": "P1"})
    with pytest.raises(Refusal):                          # the guard cannot confirm for the host
        desk.propose(W(GUARD), {"action": "confirm_guest", "visit_id": "V-example-0001", "party": "P1"})
    c.at("11:19")
    assert desk.tick() == []
    c.at("11:20")
    assert [e["kind"] for e in desk.tick()] == ["reminded"]
    assert desk.tick() == []                              # once
    c.at("11:25")
    sus = desk.tick()
    assert [e["kind"] for e in sus] == ["suspended"] and "flagged" in sus[0]["reason"]
    assert "idp:31ee-ingrid" in sus[0]["notify"] or len(sus[0]["notify"]) >= 2
    with pytest.raises(Refusal, match="suspended"):       # and the gate now says so
        entry(desk, "P1", "qr")
    with pytest.raises(Refusal, match="too late"):
        desk.propose(W(ANN), {"action": "confirm_guest", "visit_id": "V-example-0001", "party": "P1"})


def test_each_timer_step_rechecks_its_reason(desk):
    register(desk)
    c = desk.test_clock
    c.at("11:05")
    entry(desk, "P1", "qr", vehicle=True)
    c.at("11:15")
    desk.propose(W(EVA), {"action": "confirm_guest", "visit_id": "V-example-0001", "party": "P1"})
    c.at("11:30")
    assert desk.tick() == []                              # confirmed: nothing fires
    entry(desk, "P2", "visitor-badge")                    # the passenger arrives at 11:30 and leaves at 11:40
    c.at("11:40")
    desk.propose(W(GUARD), {"action": "record_departure", "visit_id": "V-example-0001", "party": "P2"})
    c.at("12:00")
    assert desk.tick() == []                              # left: nothing fires


def test_the_timeline_and_who_may_see_it(desk):
    register(desk)
    c = desk.test_clock
    c.at("11:05")
    entry(desk, "P1", "qr", vehicle=True)
    v = desk.visit_detail(W(ANN), "V-example-0001")
    kinds = [x["kind"] for x in v["timeline"]]
    assert kinds[:3] == ["qr-issued", "opens", "arrived"] and "remind-due" in kinds and "suspend-due" in kinds
    p1 = next(p for p in v["parties"] if p["party"] == "P1")
    assert p1["arrived"] and "acknowledge_arrival" in p1["actions"] and "confirm_guest" in p1["actions"]
    assert p1["gate"]["allow"] and p1["qr"]                 # the preview assumes the current code
    assert v["vehicles_detail"][0]["plate_tail"] == "111" and v["kit"][0]["count"] == 2
    assert desk.visits(W(GUARD))[0]["visit_id"] == "V-example-0001"           # the front office
    assert desk.visits(W(CARLA))[0]["visit_id"] == "V-example-0001"           # the guest themselves
    assert desk.visits(W(ANN))[0]["waiting_for_me"] == 1
    assert desk.visits(W(DIRK)) == []
    with pytest.raises(PermissionError):
        desk.visit_detail(W(DIRK), "V-example-0001")
    with pytest.raises(PermissionError):                  # unknown answers like not-yours
        desk.visit_detail(W(DIRK), "V-example-0099")
    before = desk.visit_detail(VIEWER, "V-example-0001", "2026-10-26T11:00:00Z")
    assert "arrived" not in [x["kind"] for x in before["timeline"]]


def test_a_visit_and_its_events_are_never_rewritten(desk):
    register(desk)
    desk.test_clock.at("11:05")
    entry(desk, "P1", "qr")
    doc = desk.store.load()
    changed = {**doc, "visit_events": [{**doc["visit_events"][0], "kind": "left"}]}
    assert any("changed" in e for e in records.guard(doc, changed))
    assert any("deleted" in e for e in records.guard(doc, {**doc, "visits": []}))


# --- the QR code and the phone scan (decision 0009, D2) ------------------------------------------------------------

def test_the_code_names_no_person_and_only_its_digest_is_kept(desk):
    register(desk)
    q = desk.visit_qr(W(CARLA), "V-example-0001", "P1")
    from keyclerk import qr
    payload = qr.read(q["token"])
    assert set(payload) == {"v", "p", "n", "e", "k"} and payload["p"] == "P1" and "carla" not in q["token"]
    assert q["url"].endswith("/#/scan/" + q["token"]) and q["image"].startswith("data:image/svg+xml;base64,")
    ev = [e for e in desk.store.load()["visit_events"] if e["kind"] == "qr-issued"]
    assert [(e["party"], e["serial"]) for e in ev] == [("P1", 1)] and ev[0]["qr"] == qr.digest(q["token"])
    assert q["token"] not in signed_text(desk)
    with pytest.raises(Refusal):                          # an unregistered passenger gets no code
        desk.visit_qr(W(ANN), "V-example-0001", "P2")
    with pytest.raises(PermissionError):                  # the front office does not hand out codes
        desk.visit_qr(W(GUARD), "V-example-0001", "P1")


def test_a_qr_entry_needs_the_current_code(desk):
    register(desk)
    c = desk.test_clock
    c.at("11:05")
    old = code(desk)
    desk.propose(W(CARLA), {"action": "issue_qr", "visit_id": "V-example-0001", "party": "P1"})   # lost phone: a new code
    body = {"action": "record_entry", "presented": "qr", "checkpoint": "main gate"}
    with pytest.raises(Refusal, match="newer code"):
        desk.propose(W(GUARD), {**body, "token": old})
    tampered = old[:-4] + ("AAAA" if not old.endswith("AAAA") else "BBBB")
    with pytest.raises(Refusal, match="signature|not a KeyClerk"):
        desk.propose(W(GUARD), {**body, "token": tampered})
    with pytest.raises(Refusal, match="no code was presented"):
        desk.propose(W(GUARD), {**body, "visit_id": "V-example-0001", "party": "P1"})
    r = desk.propose(W(GUARD), {**body, "token": code(desk), "vehicle": True})
    assert r["records"]["visit_events"][0]["kind"] == "arrived"


def test_the_phone_scan_says_only_yes_or_no(desk):
    register(desk)
    c = desk.test_clock
    c.at("11:05")
    tok = code(desk)
    assert desk.scan(tok) == {"unescorted": False, "checked": "online", "at": "2026-10-26T11:05:00Z", "until": None}
    entry(desk, "P1", "qr", vehicle=True)                  # checked in at the gate
    yes = desk.scan(tok)
    assert yes["unescorted"] and yes["until"] == "2026-10-26T16:00:00Z" and set(yes) == {"unescorted", "checked", "at", "until"}
    assert not desk.scan("kq1.garbage.x")["unescorted"] and not desk.scan("hello")["unescorted"]
    c.at("11:30")
    desk.tick()                                            # unconfirmed: reminded, then suspended
    c.at("11:31")
    desk.tick()
    assert not desk.scan(tok)["unescorted"]                # seen at once online
    from keyclerk import qr
    off = qr.verify_offline(desk.qr_key()["key"], tok, int(c.t.timestamp()))
    assert off["valid"] and off["mode"] == "offline" and "not seen" in off["note"]   # offline cannot see it, and says so
    log = (desk.store.path / "views.log").read_text(encoding="utf-8")
    assert "phone-scan" in log and tok not in log


# --- badges (decision 0009, D4) --------------------------------------------------------------------------------------

def test_a_restricted_badge_is_signed_out_by_two_people(desk):
    register(desk)
    desk.test_clock.at("11:05")
    r = desk.propose(W(GUARD), {"action": "issue_badge", "visit_id": "V-example-0001", "party": "P1", "kind": "restricted",
                                "badge": "RB-0007"})
    assert r["outcome"] == "pending" and any("second key" in x for x in r["reasons"])
    assert BERT in desk.changes(W(BERT))["pending"][0]["waiting_for"] or desk.changes(W(BERT))["pending"][0]["can_approve"]
    with pytest.raises(Refusal):                        # the issuer is never their own second key
        desk.approve(W(GUARD), r["change_id"])
    done = desk.approve(W(BERT), r["change_id"])
    assert done["outcome"] == "applied"
    b = desk.store.load()["badges"][0]
    assert b["kind"] == "restricted" and b["approved_by"] == [as_held(desk, BERT)] and b["badge_tail"] == "007"
    assert b["to"].startswith("2026-10-26T16:00") if isinstance(b["to"], str) else b["to"].hour == 16
    assert "RB-0007" not in signed_text(desk)


def test_a_returned_badge_no_longer_opens_the_gate(desk):
    register(desk)
    desk.test_clock.at("11:05")
    badge(desk, "P2")
    assert entry(desk, "P2", "visitor-badge")["outcome"] == "applied"
    bid = desk.store.load()["badges"][0]["badge_id"]
    desk.propose(W(GUARD), {"action": "return_badge", "badge_id": bid})
    body = {"action": "record_entry", "visit_id": "V-example-0001", "party": "P2", "presented": "visitor-badge"}
    with pytest.raises(Refusal, match="no visitor badge"):
        desk.propose(W(GUARD), body)
    v = desk.visit_detail(W(GUARD), "V-example-0001")
    assert v["badges"][0]["returned"] and "badge-returned" in [x["kind"] for x in v["timeline"]]
    with pytest.raises(Refusal):                          # only the front office hands out badges
        desk.propose(W(ANN), {"action": "issue_badge", "visit_id": "V-example-0001", "party": "P2", "kind": "visitor",
                              "badge": "VB-0043"})


# --- person-first visits (decision 0010) ---------------------------------------------------------------------------

FINN = "idp:66cc-finn"


def test_a_delegation_of_people_who_arrive_apart(desk):
    """A delegation: one registered guest who drives, one invited by name who forgot to register and walks in later,
    one unregistered companion; an escort; each person arrives on their own."""
    r = desk.propose(W(ANN), {
        "action": "register_visit", "place": "place:heverlee", "purpose": "supplier day", "organiser": EVA,
        "start": "2026-10-26T13:00:00Z", "end": "2026-10-26T14:00:00Z", "escorts": [DIRK],
        "delegation": {"name": "Example Networks", "organisation": "Example Networks"},
        "attendees": [{"anchor": CARLA, "expected": "2026-10-26T12:30:00Z"},
                      {"name": "Finn (forgot to register)", "expected": "2026-10-26T12:50:00Z", "escort": DIRK},
                      {"unregistered": True, "label": "companion"}]})
    assert r["outcome"] == "applied"
    v = r["records"]["visits"][0]
    assert [a["state"] for a in v["attendees"]] == ["registered", "invited", "unregistered"]
    assert [e["party"] for e in r["records"]["visit_events"]] == ["P1"]           # a code only for the registered one
    c = desk.test_clock
    c.at("12:30")
    entry(desk, "P1", "qr", vehicle=True)                                         # carla drives in
    with pytest.raises(Refusal, match="registered driver"):                        # nobody without identity drives in
        desk.propose(W(GUARD), {"action": "record_entry", "visit_id": v["visit_id"], "party": "P3",
                                "presented": "none", "plate": "1-ZZZ-999"})
    c.at("12:55")
    with pytest.raises(Refusal, match="front office"):                             # finn has no code yet
        entry(desk, "P2", "none")
    reg = desk.propose(W(GUARD), {"action": "register_on_site", "visit_id": v["visit_id"], "party": "P2", "anchor": FINN})
    assert [e["kind"] for e in reg["records"]["visit_events"]] == ["registered-on-site", "qr-issued"]
    finn = desk.visit_qr(W(FINN), v["visit_id"], "P2")["token"]                    # now registered: his own code
    arr = desk.propose(W(GUARD), {"action": "record_entry", "token": finn, "presented": "qr"})
    assert set(arr["records"]["visit_events"][0]["notify"]) == set(as_held(desk, ANN, EVA, DIRK))   # the escort is told too
    desk.propose(W(DIRK), {"action": "confirm_guest", "visit_id": v["visit_id"], "party": "P2"})   # escorts confirm
    d = desk.visit_detail(W(ANN), v["visit_id"])
    states = {p["party"]: (p["state"], p["came"]) for p in d["parties"]}
    assert states == {"P1": ("registered", "a vehicle"), "P2": ("registered-on-site", "on foot"), "P3": ("unregistered", None)}
    assert d["delegation"] == "Example Networks" and d["escorts"] == ["dirk"] and d["arrived"] == 2
    assert desk.visits(W(DIRK))[0]["visit_id"] == v["visit_id"]                    # an escort sees the visit


def test_someone_not_on_the_list_is_added_on_the_day(desk):
    register(desk)
    c = desk.test_clock
    c.at("12:10")
    r = desk.propose(W(GUARD), {"action": "add_attendee", "visit_id": "V-example-0001",
                                "attendee": {"name": "a colleague of carla"}})
    assert r["records"]["visit_events"][0]["kind"] == "attendee-added" and r["records"]["visit_events"][0]["party"] == "P3"
    with pytest.raises(Refusal):                                                   # a stranger cannot add people
        desk.propose(W(DIRK), {"action": "add_attendee", "visit_id": "V-example-0001", "attendee": {"name": "x"}})
    d = desk.visit_detail(W(GUARD), "V-example-0001")
    assert any(p["party"] == "P3" and p["state"] == "invited" for p in d["parties"])
    assert any(x["kind"] == "attendee-added" for x in d["timeline"])

