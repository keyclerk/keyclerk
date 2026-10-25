# SPDX-License-Identifier: EUPL-1.2
"""Decision 0022, S5 step T2: what the checking signer gives a desk on the change log. A change proposed again after
its answer was lost applies once; mapping rows for new people enter only with the commitment a record of the same
change carries; a log can start empty; a frozen signer still serves the reads a desk follows by."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import ADD, FIXTURES, change_ops, world  # noqa: F401 - world is a fixture

from keyclerk import anchors as A
from keyclerk import records
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import migrate as M
from keyclerk.store import replay as RP


def _base(s):
    return {"size": s.replica.size(), "head": s.replica.head().hex() if s.replica.head() else None}


def test_a_change_proposed_again_after_a_lost_answer_applies_once(world, tmp_path):
    s = world["signer"]
    change = {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-1a2b3c", "action": "add_member"}}
    base = _base(s)
    first = s.propose(base, copy.deepcopy(change), [])
    size = s.replica.size()
    again = s.propose(base, copy.deepcopy(change), [])           # the desk never saw the first answer
    assert again["duplicate"] == size - 1 and again["link"] == first["link"] and again["hash"] == first["hash"]
    assert again["checkpoint"] == s.replica.checkpoint(size) and s.replica.size() == size


def test_the_same_change_id_with_other_contents_is_refused_and_unrelated_stale_bases_stay_stale(world, tmp_path):
    s = world["signer"]
    ops = change_ops(tmp_path, ADD, world)
    base = _base(s)
    s.propose(base, {"ops": ops, "entry": {"change_id": "C-1a2b3c", "action": "add_member"}}, [])
    with pytest.raises(SignerRefused, match="already link"):
        s.propose(base, {"ops": ops, "entry": {"change_id": "C-1a2b3c", "action": "something else"}}, [])
    with pytest.raises(SignerRefused, match="stale"):           # another change on the old base: an ordinary refusal
        s.propose(base, {"ops": ops, "entry": {"change_id": "C-ffffff", "action": "add_member"}}, [])
    with pytest.raises(SignerRefused, match="stale"):           # a base from another history is never a duplicate
        s.propose({"size": base["size"], "head": "ab" * 32},
                  {"ops": ops, "entry": {"change_id": "C-1a2b3c", "action": "add_member"}}, [])


def _new_person(s, row):
    """The ops of a new person modelled on one the replica holds: the person with row's anchor, and the account."""
    _, rec = next(iter(s.replica.scan("persons")))
    rec = {k: v for k, v in copy.deepcopy(rec).items() if k in ("kind", "unit")}
    rec.update({"person": "finn-new", "anchors": [row["anchor"]]})
    return [_account(row), {"op": "put", "kind": "persons", "key": "finn-new", "record": rec}]


def _account(row, commit=None):
    return {"op": "put", "kind": "accounts", "key": row["anchor"],
            "record": {"anchor": row["anchor"], "commit": commit or A.commitment(row["salt"], row["idp"])}}


def test_mapping_rows_enter_only_with_the_commitment_the_change_carries(world):
    s = world["signer"]
    row = A.mapping_row("idp:a1b2-newcomer")
    other = A.mapping_row("idp:77dd-gus")
    put = _new_person(s, row)
    with pytest.raises(SignerRefused, match="enters with its mapping row"):
        s.propose(_base(s), {"ops": put, "entry": {"change_id": "C-c00001"}}, [], [other])
    with pytest.raises(SignerRefused, match="no account of the log"):     # a person whose account did not enter
        s.propose(_base(s), {"ops": put[1:], "entry": {"change_id": "C-c00008"}}, [], [])
    forged = {**row, "salt": other["salt"]}                      # the right anchor, a salt that does not commit
    with pytest.raises(SignerRefused, match="carries its commitment"):
        s.propose(_base(s), {"ops": put, "entry": {"change_id": "C-c00002"}}, [], [forged])
    assert s.replica.side_get("anchor_map", row["anchor"]) is None
    s.propose(_base(s), {"ops": put, "entry": {"change_id": "C-c00003"}}, [], [row])
    assert s.replica.side_get("anchor_map", row["anchor"]) == row
    assert s.replica.side_get("anchor_idp", A.idp_key(row["idp"])) == {"anchor": row["anchor"]}


def test_a_mapped_anchor_or_account_is_never_re_pointed(world):
    s = world["signer"]
    _, mapped = next(iter(s.replica.side_scan("anchor_map")))
    kept = s.replica.get("accounts", mapped["anchor"])
    with pytest.raises(SignerRefused, match="commitment never changes"):     # re-pointing by a new commit
        s.propose(_base(s), {"ops": [_account(mapped, "sha256:" + "b" * 64)], "entry": {"change_id": "C-c00009"}}, [],
                  [])
    with pytest.raises(SignerRefused, match="only by erasure"):
        s.propose(_base(s), {"ops": [{"op": "del", "kind": "accounts", "key": mapped["anchor"]}],
                             "entry": {"change_id": "C-c0000a"}}, [], [])
    assert s.replica.get("accounts", mapped["anchor"]) == kept
    same_account = A.mapping_row(mapped["idp"])                  # a second anchor for an account already mapped
    with pytest.raises(SignerRefused, match="has an anchor already"):
        s.propose(_base(s), {"ops": _new_person(s, same_account), "entry": {"change_id": "C-c00004"}}, [],
                  [same_account])
    same_anchor = A.mapping_row("idp:99ee-mallory", anchor=mapped["anchor"])   # the anchor pointed at someone else
    with pytest.raises(SignerRefused, match="commitment never changes"):
        s.propose(_base(s), {"ops": _new_person(s, same_anchor), "entry": {"change_id": "C-c00005"}}, [],
                  [same_anchor])
    assert s.replica.side_get("anchor_map", mapped["anchor"]) == mapped


def test_a_log_starts_empty_and_its_first_change_is_judged_against_nothing(tmp_path):
    from keyclerk import config
    config.configure(FIXTURES / "config.yaml")
    s = Signer(Ed25519PrivateKey.generate(), tmp_path / "state")
    try:
        with pytest.raises(SignerRefused, match="no change log yet"):
            s.links(0, 10)
        head = s.start("example")
        assert head["size"] == 0 and head["revision"] is None
        with pytest.raises(SignerRefused, match="starts once"):
            s.start("example")
        seed = records.loads((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
        raw_head, raw_ops, _ = M.split(seed)
        with pytest.raises(SignerRefused, match="not by an internal anchor"):     # identity provider ids: never in a link
            s.propose({"size": 0, "head": None}, {"ops": raw_head + raw_ops, "entry": {"change_id": "C-seedff"}}, [])
        rows = M.mint_rows(seed)
        head_ops, ops, _ = M.split(M.rekeyed(seed, rows))
        no_root = [o for o in head_ops if o["key"] != "root"]     # groups without a root trust owner
        with pytest.raises(SignerRefused, match="engine.s checks refuse it: .*root trust owner"):
            s.propose({"size": 0, "head": None}, {"ops": no_root + ops, "entry": {"change_id": "C-seed00"}}, [], rows)
        assert s.replica.size() == 0
        answer = s.propose({"size": 0, "head": None}, {"ops": head_ops + ops, "entry": {"change_id": "C-seed01"}}, [],
                           rows)
        assert answer["revision"] == 1 and s.replica.size() == 1 and RP.revision(s.replica) == 1
    finally:
        s.close()
    again = Signer(Ed25519PrivateKey.generate(), tmp_path / "state")      # another key: the replica is not its own
    try:
        assert again.broken
    finally:
        again.close()


def test_a_signer_with_a_yaml_revision_migrates_instead_of_starting(world):
    s = world["signer"]
    with pytest.raises(SignerRefused, match="starts once"):
        s.start("example")


def test_a_frozen_signer_serves_reads_and_signs_nothing(world, tmp_path):
    s = world["signer"]
    ops = change_ops(tmp_path, ADD, world)
    s._freeze("a test freeze")
    head = s.head()
    assert head["size"] == s.replica.size() and "a test freeze" in head["frozen"]
    assert len(s.links(0, 500)["links"]) == s.replica.size() and s.checkpoint(None)["checkpoint"]
    assert s.anchors(None, 10)["anchors"] and isinstance(s.tokens(None, 10)["tokens"], list)
    with pytest.raises(SignerRefused, match="a test freeze"):
        s.propose(_base(s), {"ops": ops, "entry": {"change_id": "C-c00006"}}, [])


def test_a_broken_signer_serves_no_reads(world):
    s = world["signer"]
    s.broken = "the signer's replica failed verification: a test"
    assert s.head() == {"broken": s.broken}
    for read in (lambda: s.links(0, 10), lambda: s.anchors(None, 10), lambda: s.checkpoint(None)):
        with pytest.raises(SignerRefused, match="failed verification"):
            read()


def test_start_and_rows_over_the_socket(world, tmp_path):
    import threading
    from keyclerk.signer import SignerClient, serve
    s = world["signer"]
    srv = serve(s, "tcp:127.0.0.1:0", "t0ken-for-tests")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        tok = tmp_path / "token"
        tok.write_text("t0ken-for-tests", encoding="utf-8")
        c = SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(tok))
        with pytest.raises(SignerRefused, match="starts once"):
            c.start("example")
        row = A.mapping_row("idp:c3d4-socket")
        h = c.head()
        c.propose({"size": h["size"], "head": h["head"]},
                  {"ops": _new_person(s, row), "entry": {"change_id": "C-c00007"}}, [], [row])
        assert s.replica.side_get("anchor_map", row["anchor"]) == row
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_subject_is_linked_once_and_never_moved(world):
    import json
    import uuid
    s = world["signer"]
    (a1, r1), (a2, _) = list(s.replica.side_scan("anchor_map"))[:2]
    sub, other = str(uuid.uuid4()), str(uuid.uuid4())
    assert s.link_subject(a1, sub) == {"linked": True} and s.link_subject(a1, sub) == {"linked": False}
    assert s.replica.side_get("anchor_map", a1) == {**r1, "sub": sub}
    assert s.replica.side_get("anchor_idp", A.sub_key(sub)) == {"anchor": a1}
    with pytest.raises(SignerRefused, match="linked to another subject"):
        s.link_subject(a1, other)
    with pytest.raises(SignerRefused, match="linked to another anchor"):
        s.link_subject(a2, sub)
    with pytest.raises(SignerRefused, match="subject"):
        s.link_subject(a2, "not-a-uuid")
    with pytest.raises(SignerRefused, match="no mapping row"):
        s.link_subject(A.new(), other)
    line = json.loads((s.state / "audit.jsonl").read_text().splitlines()[-1])
    assert line["op"] == "link_subject" and line["anchor"] == a1
