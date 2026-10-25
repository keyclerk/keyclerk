# SPDX-License-Identifier: EUPL-1.2
"""Keys and custody: credentials are things in the access-path graph, kept in keyboxes or
issued to people; doors may need one key, any of several (a master) or M of N; the checks find lockouts, keyboxes
weaker than what their keys open, master keys that collapse layers, broken dual control, sealed keys without their
safeguards, unlogged keys and single copies."""
import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import access_paths as A  # noqa: E402
from keyclerk import keys as K  # noqa: E402

G = yaml.safe_load((FIXTURES / "access-paths.yaml").read_text(encoding="utf-8"))
WALK = {"site-entry", "building-entry", "secure-floor", "server-room", "guard-room", "strongroom"}


def g():
    return copy.deepcopy(G)


def cred(graph, kid):
    return next(k for k in graph["credentials"] if k["credential_id"] == kid)


def cp(graph, cid):
    return next(c for c in graph["checkpoints"] if c["checkpoint_id"] == cid)


def test_the_demo_keys_are_clean():
    assert K.check(G) == []


def test_a_key_is_picked_up_from_its_keybox_only_by_its_holders():
    with_key = A.reachable(G, {"road"}, WALK | {"key-cabinet", "cage-a"})
    assert "cage-a" in with_key                                               # cage key released from the cabinet
    no_release = A.reachable(G, {"road"}, WALK | {"key-cabinet"})
    assert "cage-a" not in no_release                                         # the cabinet keeps the cage key
    no_cabinet = A.reachable(G, {"road"}, WALK | {"cage-a"})
    assert "cage-a" not in no_cabinet


def test_route_names_the_missing_key_and_where_it_is_kept():
    r = A.route(G, "lockbox-a1", WALK | {"key-cabinet", "cage-a", "rack-a1", "lockbox-a1"}, requester="idp:91d0-bert")
    assert r["missing"] == ["lockbox-a1-code"]
    assert r["missing_keys"] == {"lockbox-a1-code": {"lockbox-code-half-2": "issued"}}   # Ingrid holds the other half
    assert r["prerequisites"] == []


def test_a_key_behind_its_own_door_is_a_lockout():
    bad = g()
    cred(bad, "cage-key-a")["stored_in"] = "rack-a1"
    assert "cage-key-a: every copy is out of reach (lockout)" in K.check(bad)


def test_a_keybox_weaker_than_what_its_keys_open_is_a_finding():
    bad = g()
    cp(bad, "key-cabinet-release")["from"] = "lobby"                         # the cabinet moved to reception
    errs = K.check(bad)
    assert any(e.startswith("cage-key-a: kept in key-cabinet with 3 independent layers, but it leads to Restricted")
               for e in errs)


def test_a_master_key_across_doors_counts_once():
    assert A.weakest(G, "lockbox-a1")["layers"] == 5
    bad = g()
    cp(bad, "rack-a1-lock")["keys"] = {"m": 1, "of": ["rack-key-a1", "master-key-1"]}
    cp(bad, "rack-a1-lock")["depends_on"] = ["cage-lock"]                    # the same lock series
    bad["credentials"].append({"credential_id": "rack-key-a1", "kind": "mechanical_key", "stored_in": "key-cabinet",
                               "release_requires": "rack-a1", "logged": True, "copies": 2})
    assert A.weakest(bad, "lockbox-a1")["layers"] == 4


def test_dual_control_breaks_when_one_person_holds_or_can_gather_both_halves():
    bad = g()
    cred(bad, "lockbox-code-half-2")["held_by"] = ["idp:91d0-bert"]
    assert "lockbox-a1-code: idp:91d0-bert holds 2 of its keys (dual control)" in K.check(bad)
    bad = g()
    cred(bad, "lockbox-code-half-2").pop("held_by")
    cred(bad, "lockbox-code-half-2")["stored_in"] = "key-cabinet"
    errs = K.check(bad, people={"idp:91d0-bert": WALK | {"key-cabinet"}})
    assert "lockbox-a1-code: idp:91d0-bert can gather 2 of its keys alone (dual control)" in errs   # half 1 in hand
    cred(bad, "lockbox-code-half-1").pop("held_by")
    cred(bad, "lockbox-code-half-1")["stored_in"] = "key-cabinet"
    assert any("share a store" in e for e in K.check(bad))


def test_sealed_keys_need_their_safeguards():
    bad = g()
    cp(bad, "breakglass-open").pop("alarm")
    cred(bad, "master-key-backup")["on_use"] = "keep"
    errs = K.check(bad)
    assert "master-key-backup: a sealed key's store is two-person, alarmed and tamper-evident on every way in" in errs
    assert "master-key-backup: a sealed key is replaced (rekeyed) after every use" in errs


def test_unlogged_and_single_copy_keys_on_the_way_to_restricted():
    bad = g()
    cred(bad, "cage-key-a")["logged"] = False
    cred(bad, "cage-key-a")["copies"] = 1
    errs = K.check(bad)
    assert "cage-key-a: leads to Restricted but its use is not logged" in errs
    assert "cage-key-a: leads to Restricted with a single copy and no sealed backup" in errs


def test_the_bmc_password_from_the_vault_opens_the_console_of_the_rack():
    who = WALK | {"key-cabinet", "cage-a", "rack-a1", "bmc-a1", "paw-holder", "paw-login", "admin-overlay",
                  "openbao-bmc-read"}
    dev = {"paw-device", "admin-overlay-device"}
    assert "keyclerk-portal" in A.reachable(G, {"road", "internet"}, who, dev)
    assert "keyclerk-portal" not in A.reachable(G, {"road", "internet"}, who - {"openbao-bmc-read"}, dev)


# --- the adversarial review's rules (KY) --------------------------------------------------------------------------

def test_one_person_never_crosses_a_two_person_checkpoint_and_routes_name_the_second_person():
    everything = {x["requires"] for x in G["checkpoints"]}
    alone = A.reachable(G, {"road"}, everything, everything, anchor="idp:91d0-bert")
    assert "breakglass-safe" not in alone and "lockbox-a1" not in alone
    r = A.route(G, "lockbox-a1", everything, everything, requester="idp:91d0-bert")
    assert r["second_person"] == ["lockbox-a1-code"]


def test_backups_of_two_shares_in_one_store_break_dual_control():
    bad = g()
    cred(bad, "lockbox-code-backup-1")["stored_in"] = "breakglass-safe"
    assert any("share a store ['breakglass-safe']" in e for e in K.check(bad))


def test_a_keybox_declares_its_admin_and_override():
    bad = g()
    bad["checkpoints"] = [c for c in bad["checkpoints"] if c["kind"] not in ("admin", "override") or c["to"] != "key-cabinet"]
    assert "key-cabinet: a keybox declares its admin and override paths (or no_override)" in K.check(bad)


def test_copy_resistance_secret_rotation_and_issued_keys():
    bad = g()
    cred(bad, "cage-key-a").pop("copy_resistance")
    cred(bad, "bmc-a1-password").pop("on_read")
    cred(bad, "lockbox-code-half-1").pop("on_leaver")
    errs = K.check(bad)
    assert any(e.startswith("cage-key-a: a possession key to Restricted declares its copy resistance") for e in errs)
    assert "bmc-a1-password: a secret read is a secret held: dynamic, or rotated on read" in errs
    assert any(e.startswith("lockbox-code-half-1: an issued key to Restricted is revoked or changed") for e in errs)


def test_a_cabinet_that_stays_shut_on_power_loss_needs_an_override():
    bad = g()
    bad["checkpoints"] = [c for c in bad["checkpoints"] if c["checkpoint_id"] != "key-cabinet-override"]
    bad["credentials"] = [k for k in bad["credentials"] if k["credential_id"] != "cabinet-override-key"]
    errs = K.check(bad)
    assert "cage-key-a: every copy is out of reach (power) (lockout)" in errs


def test_sealed_keys_stay_out_of_routine_routes():
    who = WALK | {"break-glass", "cage-a", "rack-a1"}
    assert "master-key-1" not in A.obtainable_keys(G, who, who)
    assert "cage-a" not in A.reachable(G, {"road"}, who - {"cage-a"})


def test_logged_must_be_backed_by_a_recording_checkpoint():
    bad = g()
    for c in bad["checkpoints"]:
        if c["to"] == "openbao":
            c.pop("records_passage", None)
    assert "bmc-a1-password: declared logged, but nothing on its way records it" in K.check(bad)
