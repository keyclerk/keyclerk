# SPDX-License-Identifier: EUPL-1.2
"""The desk core: actions become records the engine checks; keys someone else must add make a change wait."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import records
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
ANN, BERT, EVA = W("idp:7c1f-ann"), W("idp:91d0-bert"), W("idp:55bb-eva")
VIEWER = {"anchor": None, "roles": ["keyclerk-viewer"]}


@pytest.fixture(params=["yaml", "sqlite"])
def desk(request, tmp_path):
    """The desk on both stores (decision 0022 S5): the signed YAML store, and the change log through a signer."""
    if request.param == "sqlite":
        from keyclerk.signer import Signer
        from keyclerk.store.log_desk import LogStore
        signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
        d = Desk(LogStore(tmp_path / "store", signer, FIXTURES / "records.yaml"))
        yield d
        d.store.close()
        signer.close()
        return
    yield yaml_desk(tmp_path)


@pytest.fixture
def ydesk(tmp_path):
    """The YAML store alone: its records file, its key and its repair at start."""
    return yaml_desk(tmp_path)


def yaml_desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))


def test_nesting_a_group_someone_else_manages_waits_for_that_managers_key(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    assert r["outcome"] == "pending" and "manager's key" in r["reasons"][0]
    assert desk.approve(BERT, r["change_id"])["outcome"] == "applied"          # bert manages the sites subtree


def test_a_revision_the_desk_writes_keeps_history_with_its_seed(desk):
    seed = records.load(FIXTURES / "records.yaml")
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    if hasattr(desk.store, "follower"):              # the change log keeps the seed re-keyed (decision 0028)
        from keyclerk.store import migrate as M
        seed = M.rekeyed(seed, [r for _, r in desk.store.store.side_scan("anchor_map")])
    assert records.guard(seed, desk.store.load()) == []                        # times rewritten as text, same meaning


def test_actions_outside_what_one_holds_are_refused_before_the_checks(desk):
    with pytest.raises(Refusal, match="no delegation"):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    with pytest.raises(Refusal, match="unknown action"):
        desk.propose(ANN, {"action": "grant_everything"})
    with pytest.raises(PermissionError):
        desk.propose({"anchor": None, "roles": ["keyclerk-viewer"]}, {"action": "add_member", "group": "office-staff",
                                                                         "anchor": "idp:66cc-finn"})


def test_refused_attempts_are_on_record_with_their_reason(desk):
    with pytest.raises(Refusal):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:7c1f-ann"})
    log = desk.changes(VIEWER)["log"]
    assert [e["outcome"] for e in log[:2]] == ["refused", "refused"]
    assert [e["outcome"] for e in desk.changes(ANN)["log"]][:1] == ["refused"]    # ann sees her own, not eva's
    assert "added themselves" in log[0]["reasons"][0] and "no delegation" in log[1]["reasons"][0]
    assert log[0]["actor_name"] == "ann" and desk.store.verify_log() == []


def test_one_person_cannot_flood_the_desk_and_throttled_attempts_are_not_logged(desk, monkeypatch):
    from keyclerk import desk as desk_module
    monkeypatch.setattr(desk_module, "WRITES_PER_WINDOW", 5)
    for _ in range(5):
        with pytest.raises(Refusal):
            desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    n = len(desk.store.log())
    with pytest.raises(desk_module.Throttled):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    assert len(desk.store.log()) == n
    assert desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn",
                              "days": 30})["outcome"] == "applied"           # someone else is not held up


def test_the_log_reads_from_its_end_and_a_broken_line_is_named_not_fatal(desk, monkeypatch):
    from keyclerk import desk as desk_module
    monkeypatch.setattr(desk_module, "LOG_TAIL_BYTES", 6000)
    for i in range(300):
        desk.store._append({"change_id": f"C-{i}", "action": "x", "outcome": "refused", "reasons": []})
    tail = desk.store.log(limit=5)
    assert [e["change_id"] for e in tail] == [f"C-{i}" for i in range(295, 300)]
    assert desk.store.verify_log() == []
    with (desk.store.path / "log.jsonl").open("a", encoding="utf-8") as h:
        h.write("not json\n")
    desk.store._verified = (0, "0" * 64, [], 0, 0.0)
    assert desk.store.verify_log() == ["log line 302 does not chain or is not signed by this desk"]
    assert desk.changes(VIEWER)["log"][0]["outcome"] == "unreadable"


def test_a_change_that_needs_two_keys_collects_them_one_by_one(desk, monkeypatch):
    real = Desk._errors

    finn, eva, bert = (desk.store.inward(a) or a for a in ("idp:66cc-finn", "idp:55bb-eva", "idp:91d0-bert"))

    def errors(self, doc):                           # the new membership needs eva's key and bert's key
        out = set(real(self, doc))
        for m in doc.get("memberships", []):
            if m["member"].get("anchor") == finn and m["group"] == "office-staff":
                if eva not in m.get("approved_by", []):
                    out.add(f"{m['membership_id']}: needs a second key")
                if bert not in m.get("approved_by", []):
                    out.add(f"{m['membership_id']}: needs the manager's key")
        return out
    monkeypatch.setattr(Desk, "_errors", errors)
    desk.store.scoped_judging = False                # the rule above is added to the full check: judge in full
    r = desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    assert r["outcome"] == "pending" and len(r["reasons"]) == 2
    pend = desk.changes(EVA)["pending"][0]
    assert pend["can_approve"]
    first = desk.approve(EVA, r["change_id"])
    assert first["outcome"] == "pending" and len(first["reasons"]) == 1 and "manager's key" in first["reasons"][0]
    with pytest.raises(Refusal, match="approved this change already"):
        desk.approve(EVA, r["change_id"])
    assert not desk.changes(EVA)["pending"][0]["can_approve"]
    assert desk.changes(BERT)["pending"][0]["approvals"] == [eva]
    done = desk.approve(BERT, r["change_id"])
    assert done["outcome"] == "applied"
    assert sorted(done["records"]["memberships"][0]["approved_by"]) == sorted([eva, bert])   # the desk keeps them sorted


def test_every_revision_the_desk_signs_carries_its_serial(desk):
    assert desk.store.load()["revision"] == 1 == desk.store.revision()          # the seed is revision 1
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    assert desk.store.load()["revision"] == 2 == desk.store.revision()


def _restart(desk):
    desk.store.close()
    return Desk(Store(desk.store.path, desk.store.key_path))


def test_changes_waiting_at_once_never_share_a_record_id_and_the_engine_refuses_shared_ids(desk):
    a = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    b = desk.propose(ANN, {"action": "include_group", "group": "office", "include": "site-wilsele", "days": 30})
    assert a["records"]["memberships"][0]["membership_id"] != b["records"]["memberships"][0]["membership_id"]
    assert desk.approve(BERT, a["change_id"])["outcome"] == desk.approve(BERT, b["change_id"])["outcome"] == "applied"
    doc = desk.store.load()
    assert records.duplicate_ids(doc) == []
    doc["memberships"].append(dict(doc["memberships"][-1]))
    assert any("used by more than one" in e for e in records.duplicate_ids(doc))


def test_an_add_that_already_holds_or_already_waits_is_refused(desk):
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    with pytest.raises(Refusal, match="already holds"):
        desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    with pytest.raises(Refusal, match="already waits"):
        desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})


def test_one_desk_per_store(ydesk):
    from keyclerk.desk import StoreFault
    with pytest.raises(StoreFault, match="one writer"):
        Store(ydesk.store.path, ydesk.store.key_path)


def test_a_restart_repairs_what_a_crash_leaves_and_says_so(ydesk):
    ydesk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    good = ydesk.store.raw()
    with (ydesk.store.path / "log.jsonl").open("ab") as h:
        h.write(b'{"seq": 9, "ha')                                     # cut in the middle of an append
    (ydesk.store.path / "pending.json").write_text("{not json", encoding="utf-8")
    (ydesk.store.path / "revisions" / "000003.yaml").write_bytes(b"realm: x\n")   # written ahead, never committed
    (ydesk.store.path / "records.yaml").write_bytes(good[:40])          # cut before its rename finished
    d2 = _restart(ydesk)
    assert len(d2.store.recovered) == 3 and d2.store.raw() == good and d2.store.revision() == 2
    assert d2.store.verify_log() == [] and d2.changes(ANN)["pending"] == []
    assert d2.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:77dd-gina",
                            "days": 30})["revision"] == 3


def test_records_changed_outside_the_desk_are_never_signed_by_it(ydesk):
    good = ydesk.store.raw()
    (ydesk.store.path / "records.yaml").write_bytes(good.replace(b"office-staff", b"office-stuff", 1))
    assert ydesk.store.raw() == good                                     # the vouched revision is published again
    assert ydesk.store.log(1)[0]["outcome"] == "recovered"
    (ydesk.store.path / "revisions" / "000001.yaml").write_bytes(b"realm: forged\n")
    (ydesk.store.path / "records.yaml").write_bytes(b"realm: forged\n")
    from keyclerk.desk import StoreFault
    with pytest.raises(StoreFault, match="restore"):
        ydesk.store.raw()


def test_a_store_whose_log_carries_no_signature_of_this_desk_does_not_start(desk, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
    from keyclerk.desk import StoreFault
    other = tmp_path / "other-key"
    other.write_text(K.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk.store.close()
    with pytest.raises(StoreFault, match="signature"):
        Store(desk.store.path, other)


def test_a_plain_member_sees_only_what_they_need(desk):
    FINN = W("idp:66cc-finn")
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    with pytest.raises(Refusal):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    with pytest.raises(PermissionError):
        desk.people(FINN)                                                 # the directory is for managers
    with pytest.raises(PermissionError):
        desk.broker(FINN)
    seen = {g["group_id"] for g in desk.groups(FINN)}
    assert "office-staff" in seen and "finance" not in seen               # his own group and those above it
    with pytest.raises(LookupError, match="manage or belong to"):
        desk.group(FINN, "finance")
    with pytest.raises(LookupError, match="manage or belong to"):
        desk.group(FINN, "no-such-group")                                 # the same answer: no existence oracle
    assert desk.delegations(FINN) == []
    log = desk.changes(FINN)["log"]
    assert log and all("finn" in e["summary"] for e in log)               # only the change about him, not eva's attempt
    with pytest.raises(PermissionError):
        desk.person(FINN, "idp:no-such-person")                           # permission before lookup
    assert len(desk.groups(ANN)) > len(seen) and desk.people(ANN)          # a manager sees her subtree and the directory


def test_the_identifier_check_still_covers_every_identifier_field():
    from keyclerk import records as R
    assert isinstance(R.ID_FIELDS, set) and {"by", "under", "group", "membership_id"} <= R.ID_FIELDS
    doc = R.load(FIXTURES / "records.yaml")
    doc["memberships"][0]["under"] = "D bad id with spaces"
    assert any("under" in e or "identifier" in e for e in R.validate(doc))


def test_the_records_are_parsed_once_per_revision_and_handed_out_as_copies(desk, monkeypatch):
    """Found in a review (2026-10-23): a parse grows with the records, so the desk parses once per revision; each request
    gets its own copy, so changing it changes nothing for the next."""
    from keyclerk import records as R
    d = desk
    d.store.load()                                             # warm: whatever the first load costs
    calls = []
    real = R.loads
    monkeypatch.setattr(R, "loads", lambda text: calls.append(1) or real(text))
    first = d.store.load()
    first["persons"].clear()                                   # a request scribbling on its copy
    second = d.store.load()
    assert second["persons"] and calls == []                   # no parse for the same revision; the scribble did not leak
    d.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5})
    d.store.load()
    assert calls.count(1) <= 1                                 # a write parses what it wrote once, the next load not again


def test_the_member_of_a_change_is_never_offered_as_its_second_key(desk):
    """Seen in the desk on 2026-10-23: dirk was listed as able to add the key to his own membership; the engine refused
    his key, but the list said otherwise. A key that does not count is no progress."""
    r = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:44aa-dirk"})
    assert r["outcome"] == "pending"
    waiting = desk.store.pending()[r["change_id"]]["waiting_for"]
    assert waiting and not any("44aa-dirk" in w for w in waiting)
