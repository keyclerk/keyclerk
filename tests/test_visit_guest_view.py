# SPDX-License-Identifier: EUPL-1.2
"""A guest sees their own entry in full and only the names of the other guests: not their vehicles, kit or gate
times (decision 0009, amended for review 2026-10-26 C5). The host, the organiser and the front office see it whole."""
import pytest
from tests.test_visits import ANN, CARLA, DIRK, EVA, LAB, W, visit_desk


@pytest.fixture
def desk(tmp_path):
    d = visit_desk(tmp_path)
    r = d.propose(W(ANN), {
        "action": "register_visit", "place": "place:heverlee", "host": ANN, "organiser": EVA, "purpose": "supplier meeting",
        "start": "2026-10-26T13:00:00Z", "end": "2026-10-26T14:00:00Z", "zones": [LAB],
        "attendees": [{"anchor": CARLA, "kit": [{"class": "it-device", "count": 2}]}, {"anchor": DIRK}],
        "vehicles": [{"plate": "2-XXX-111", "make": "Toyota", "model": "RAV4", "colour": "black", "driver": 1}]})
    assert r["outcome"] == "applied", r
    yield d
    d.store.close()


def _party(view, anchor_name):
    return next(p for p in view["parties"] if p["name"] == anchor_name)


def test_a_guest_sees_the_other_guests_names_only(desk):
    v = desk.visit_detail(W(DIRK), "V-example-0001")
    carla = next(p for p in v["parties"] if p.get("anchor") != DIRK and p["party"] != _own(v, DIRK))
    assert set(carla) == {"party", "name"}
    assert v["vehicles"] == [] and v["vehicles_detail"] == []
    assert not [x for x in v["timeline"] if x.get("party") == carla["party"]]
    mine = next(p for p in v["parties"] if p.get("anchor") == DIRK)
    assert {"gate", "kit", "arrived"} <= set(mine)


def test_the_driver_sees_their_own_vehicle_and_kit(desk):
    v = desk.visit_detail(W(CARLA), "V-example-0001")
    mine = next(p for p in v["parties"] if p.get("anchor") == CARLA)
    assert mine["kit"] and v["vehicles"] and v["vehicles_detail"]
    other = next(p for p in v["parties"] if p is not mine)
    assert set(other) == {"party", "name"}


def test_the_list_hides_other_guests_vehicles_too(desk):
    assert [x["vehicles"] for x in desk.visits(W(DIRK))] == [[]]
    assert [len(x["vehicles"]) for x in desk.visits(W(CARLA))] == [1]


def test_the_host_still_sees_the_visit_whole(desk):
    v = desk.visit_detail(W(ANN), "V-example-0001")
    assert all({"gate", "kit", "arrived"} <= set(p) for p in v["parties"])
    assert v["vehicles"] and v["vehicles_detail"]


def _own(view, anchor):
    return next((p["party"] for p in view["parties"] if p.get("anchor") == anchor), None)


def test_a_guest_sees_no_other_guests_kit_or_badges(desk):
    v = desk.visit_detail(W(DIRK), "V-example-0001")
    assert v["kit"] == [] and all(b["party"] == _own(v, DIRK) for b in v["badges"])
