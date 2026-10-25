# SPDX-License-Identifier: EUPL-1.2
"""Access paths: one graph for physical and digital access; possible presence with
tailgating, routes with one escort or a broker, the weakest way in by independent dependencies and per scenario,
exits as ways in, consoles of hosting racks, two-person checkpoints, obligations, free ways out."""
import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import access_paths as A  # noqa: E402

G = yaml.safe_load((FIXTURES / "access-paths.yaml").read_text(encoding="utf-8"))
TECH = {"site-entry", "building-entry", "secure-floor", "server-room", "cage-a", "rack-a1", "lockbox-a1"}


def g():
    return copy.deepcopy(G)


def cp(graph, cid):
    return next(c for c in graph["checkpoints"] if c["checkpoint_id"] == cid)


def test_the_demo_is_clean_against_the_catalogue():
    assert A.main([]) == 0


def test_possible_presence_assumes_tailgating_where_nothing_resists_it():
    strict = A.possible_presence(G, "main-door", {"site-entry", "building-entry"}, tailgating=False)
    assert strict == {"lobby", "yard", "road"}
    loose = A.possible_presence(G, "main-door", {"site-entry", "building-entry"})
    assert "hallway" in loose and "server-room" not in loose        # the loading dock does not resist; the mantrap does


def test_a_lockbox_needs_every_checkpoint_and_key_on_a_way_in_or_one_escort_for_the_whole_rest():
    keyholder = TECH | {"guard-room", "strongroom", "key-cabinet"}
    r = A.route(G, "lockbox-a1", {"site-entry", "building-entry", "secure-floor", "lockbox-a1"}, requester="idp:55bb-eva",
                others={"idp:91d0-bert": keyholder, "idp:44aa-dirk": {"server-room"}, "idp:55bb-eva": keyholder})
    assert r["missing"] == ["server-room-door", "cage-a-door", "rack-a1-lock", "lockbox-a1-code"]
    assert r["prerequisites"] == ["rack-a1", "server-room"]
    assert r["missing_keys"]["cage-a-door"] == {"cage-key-a": "key-cabinet", "master-key-1": "key-cabinet"}
    assert r["escorts"] == []                                                       # the rack lock allows no escort
    r2 = A.route(G, "cage-a", {"site-entry", "building-entry", "secure-floor"}, requester="idp:55bb-eva",
                 others={"idp:91d0-bert": keyholder, "idp:44aa-dirk": {"server-room"}, "idp:55bb-eva": keyholder})
    assert r2["escorts"] == ["idp:91d0-bert"]               # holds the rest of the way and can fetch the cage key


def test_shared_dependencies_count_once():
    s = A.weakest(G, "lockbox-a1")
    assert s["layers"] == 5                                    # guard, PACS (one head-end, one badge), cage, rack, code
    bad = g()
    for cid in ("cage-a-door", "rack-a1-lock"):
        cp(bad, cid)["depends_on"] = ["pacs-headend"]          # the cage and rack moved onto the PACS
    assert A.weakest(bad, "lockbox-a1")["layers"] == 3
    assert any(e.startswith("lockbox-a1: Restricted needs 4") for e in A.check(bad))


def test_a_fire_release_is_its_own_scenario():
    assert A.weakest(G, "lockbox-a1", "fire")["layers"] == 4
    bad = g()
    cp(bad, "cage-a-door")["fails"] = {"fire": "open"}
    assert any("(fire)" in e and "lockbox-a1" in e for e in A.check(bad))


def test_an_emergency_exit_is_a_way_in():
    bad = g()
    cp(bad, "hallway-fire-exit")["depends_on"] = ["pacs-headend"]    # the exit alarm runs on the PACS too
    for cid in ("site-gate",):
        cp(bad, cid)["requires"] = "free"
    w = A.weakest(bad, "server-room")
    assert w["layers"] == 1


def test_the_console_of_the_hosting_rack_is_a_way_in_to_the_workload_and_needs_the_vaulted_password():
    r = A.route(G, "keyclerk-portal", TECH | {"bmc-a1", "guard-room", "strongroom", "key-cabinet"})
    assert r["path"][-1] == "console:rack-a1>keyclerk-portal"
    assert r["missing_keys"] == {"console:rack-a1>keyclerk-portal": {"bmc-a1-password": "openbao"}}   # physical needs digital
    assert A.weakest(G, "keyclerk-portal")["layers"] >= 3


def test_restricted_needs_a_two_person_checkpoint_on_every_way_in():
    bad = g()
    cp(bad, "proof-vault-kas")["two_person"] = False
    assert "proof-vault: a way in without a two-person checkpoint" in A.check(bad)


def test_a_vpn_that_skips_the_privileged_workstation_is_found():
    bad = g()
    bad["checkpoints"].append({"checkpoint_id": "home-vpn", "from": "internet", "to": "admin-overlay",
                               "kind": "network_admission", "layer": "network", "pep": "NetBird",
                               "requires": "admin-overlay", "depends_on": ["netbird-management"]})
    assert any(e.startswith("proof-vault: Restricted needs 4") and "home-vpn" in e for e in A.check(bad))


def test_the_device_and_the_person_both_need_admission():
    person = {"paw-holder", "paw-login", "admin-overlay", "keyclerk-portal", "grant-records-read"}
    assert "grant-records" in A.reachable(G, {"internet"}, person, device={"paw-device", "admin-overlay-device"})
    assert "admin-overlay" not in A.reachable(G, {"internet"}, person, device={"paw-device"})


def test_obligations_add_up_and_a_digital_gap_needs_a_broker_service():
    r = A.route(G, "proof-vault", {"paw-holder", "paw-login", "admin-overlay", "keyclerk-portal"},
                device={"paw-device", "admin-overlay-device"})
    assert r["missing"] == ["proof-vault-kas"] and r["broker"] == ["proof-vault-kas"] and r["escorts"] == []
    assert r["obligations"] == ["masked", "no_export", "recorded", "view_only"]
    bad = g()
    cp(bad, "grant-records-rbac")["obligations"].append("no_print")
    assert any("cannot enforce no_print" in e for e in A.check(bad))


def test_a_portable_container_lock_is_delay_only():
    bad = g()
    next(n for n in bad["nodes"] if n["node_id"] == "lockbox-a1")["portable"] = True
    assert A.weakest(bad, "lockbox-a1")["layers"] == 4


def test_a_space_without_a_free_way_out_and_missing_fields_are_findings():
    bad = g()
    cp(bad, "cage-a-door").pop("exit")
    assert "cage-a: no free way out to an entrance (life safety)" in A.check(bad)
    bad = g()
    cp(bad, "cage-a-door").pop("depends_on")
    assert any("missing ['depends_on']" in e for e in A.check(bad))
