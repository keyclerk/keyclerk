# SPDX-License-Identifier: EUPL-1.2
"""The bundle key in the checking signer (0021 point 1, stage 3a): the signer builds a bundle from its own replica,
so a taken-over desk can delay or drop leases, never add one, and never point a lease at another bastion account."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import identity_map as M
from keyclerk.desk import Desk, Store
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store.log_desk import LogStore

from test_visits import FIXTURES

POLICY = {"modules": {}, "release": None, "entrypoints": []}


@pytest.fixture
def core(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer")
    Store(tmp_path / "seed", None, FIXTURES / "records.yaml", signer=signer).close()
    signer.migrate()
    signer.background_check()
    store = LogStore(tmp_path / "desk", signer)
    desk = Desk(store)
    signer.bundle_public()                        # the key is read before the first edge is enrolled
    a = {p["person"]: p["anchors"][0] for p in store.load()["persons"]}
    w = lambda n: {"anchor": a[n], "roles": []}                           # noqa: E731
    officer, edge_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    st = E.officer_statement("plant-a", a["eva"], E.public_hex(officer), [E.node(E.public_hex(edge_key), None, None)],
                             "enrolment")
    r = desk.propose(w("owner"), {
        "action": "enrol_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(edge_key), "officer": a["eva"],
        "officer_key": E.public_hex(officer), "profile": "assured", "statement": E.cosign(edge_key, E.cosign(officer, st)),
        "custodians": [a["finn"], a["gina"]],
        "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console", "max_session_hours": 2}]})
    assert desk.approve(w("ingrid"), r["change_id"])["outcome"] == "applied"
    reconciler = Ed25519PrivateKey.generate()
    signer.configure_identity(E.public_hex(reconciler))
    yield {"signer": signer, "a": a, "officer": officer, "reconciler": reconciler, "realm": store.load()["realm"],
           "desk": desk, "w": w}
    store.close()
    signer.close()


def ceiling(c, serial=1, persons=None, **kw):
    return E.seal_ceiling(c["officer"], {
        "format": E.CEILING_FORMAT, "edge": "plant-a", "serial": serial, "persons": persons or [c["a"]["ann"]],
        "roles": ["admins"], "targets": ["plc-ssh"], "classes": ["low", "elevated", "privileged"],
        "max_lease_hours": 24 * 366, "max_offline_hours": 12, "profile": "assured", "remote_reach": "off",
        "ports": [22], "signed_at": "2026-10-23T10:00:00Z", **kw})


def idmap(c, at=None, names=None):
    return M.seal(c["reconciler"], c["realm"], 1, at or datetime.now(timezone.utc),
                  names if names is not None else {c["a"]["ann"]: "ann"}, {})


def seal(c, serial=1, **kw):
    req = {"edge_id": "plant-a", "serial": serial, "ceiling": ceiling(c), "policy": POLICY, "attested": "basic",
           "first_seen": {}, "identity_map": idmap(c), **kw}
    return c["signer"].seal_bundle(req)


def opened(c, got):
    return E.unseal(got["bundle"], c["signer"].bundle_public()["key"], E.BUNDLE_FORMAT)


def test_the_signer_derives_the_leases_and_names_them_from_the_identity_map(core):
    got = seal(core)
    body = opened(core, got)
    ann = [x for x in body["leases"] if x["person"] == core["a"]["ann"]]
    assert ann and all(x["username"] == "ann" for x in ann), (got["dropped"], body["leases"])
    assert body["records_head"]["size"] == core["signer"].replica.size()


def test_nothing_the_desk_sends_adds_a_lease(core):
    forged = {"lease_id": "L-forged", "person": core["a"]["eva"], "target": "plc-ssh", "role": "operator",
              "class": "privileged", "roles": ["admins"], "from": "2026-01-01T00:00:00Z", "until": "2099-01-01T00:00:00Z"}
    body = opened(core, seal(core, leases=[forged], visits=[forged], revoked=[]))
    assert "L-forged" not in {x["lease_id"] for x in body["leases"] + body["visit_leases"]}


def test_a_username_the_identity_map_does_not_hold_is_never_in_a_bundle(core):
    body = opened(core, seal(core, identity_map=idmap(core, names={})))
    assert all(x["username"] is None for x in body["leases"])


def test_no_pinned_reconciler_key_an_unknown_key_or_an_older_map_is_refused(core):
    s = core["signer"]
    s.configure_identity(None)
    with pytest.raises(SignerRefused, match="no reconciler key"):
        seal(core)
    s.configure_identity(E.public_hex(core["reconciler"]))
    with pytest.raises(SignerRefused, match="pinned"):
        seal(core, identity_map=M.seal(Ed25519PrivateKey.generate(), core["realm"], 1, datetime.now(timezone.utc), {}, {}))
    seal(core, serial=1)
    with pytest.raises(SignerRefused, match="replay"):
        seal(core, serial=2, identity_map=idmap(core, at=datetime.now(timezone.utc) - timedelta(days=1)))


def test_a_serial_never_goes_back(core):
    assert seal(core, serial=5)["serial"] == 5
    for serial, want in ((5, 6), (4, 7)):                 # a desk restored older moves up, never back
        got = seal(core, serial=serial)
        assert got["serial"] == want and opened(core, got)["serial"] == want


def test_an_older_wider_ceiling_cannot_come_back(core):
    seal(core, serial=1, ceiling=ceiling(core, serial=3))
    got = seal(core, serial=2, ceiling=ceiling(core, serial=2, persons=[core["a"]["ann"], core["a"]["eva"]]))
    assert got["why"] and "older" in got["why"][0] and opened(core, got)["leases"] == []


def test_a_ceiling_by_another_key_gives_no_leases(core):
    other = dict(core, officer=Ed25519PrivateKey.generate())
    got = seal(core, ceiling=ceiling(other))
    assert got["why"] and opened(core, got)["leases"] == [] and opened(core, got)["ceiling"] is None


def test_a_first_seen_time_in_the_future_is_ignored(core):
    got = seal(core, first_seen={"L-x": "2099-01-01T00:00:00Z", "L-y": "not a time"})
    assert got["first_seen"] == {}


def test_a_bundle_key_that_went_missing_after_a_seal_is_never_replaced(core, tmp_path):
    seal(core)
    s = core["signer"]
    (s.state / "edge" / "bundle.key").unlink()
    s._edges._key = None
    with pytest.raises(SignerRefused, match="cut every one of them off"):
        seal(core, serial=2)


def test_a_signer_with_enrolled_edges_and_no_key_never_makes_one(core, tmp_path):
    """An upgrade whose desk copy was deleted, not imported: the new signer has sealed nothing yet, but its records
    name an edge that pinned the old key. A fresh key would cut that edge off."""
    s = core["signer"]
    (s.state / "edge" / "bundle.key").unlink()
    (s.state / "edge" / "serials.json").unlink(missing_ok=True)
    s._edges._key = None
    with pytest.raises(SignerRefused, match="import-bundle-key"):
        s.bundle_public()


def test_a_desks_bundle_key_moves_into_the_signer_once(core, tmp_path):
    s = core["signer"]
    (s.state / "edge" / "bundle.key").unlink()          # a signer that holds no key yet: the upgrade from 0.28
    s._edges._key = None
    desk_key = tmp_path / "bundle.key"
    E.load_or_make_key(desk_key, allow_create=True)
    pub = E.public_hex(E.load_or_make_key(desk_key, allow_create=False))
    assert s.edges().import_key(desk_key)["key"] == pub == s.bundle_public()["key"]
    other = tmp_path / "other.key"
    E.load_or_make_key(other, allow_create=True)
    from keyclerk.edge_sealer import EdgeRefused
    with pytest.raises(EdgeRefused, match="another bundle key"):
        s.edges().import_key(other)


# --- stage 3c: every other object an edge verifies under the bundle key ------------------------------------------

def test_a_time_answer_carries_the_signers_clock_and_echoes_the_nonce(core):
    m = opened_kind(core, core["signer"].seal_edge({"kind": "time", "edge_id": "plant-a", "fields": {"nonce": "n-7"}}),
                    E.TIME_FORMAT)
    assert m["nonce"] == "n-7" and abs((E._ts(m["issued"]) - datetime.now(timezone.utc)).total_seconds()) < 60
    with pytest.raises(SignerRefused, match="nonce"):
        core["signer"].seal_edge({"kind": "time", "edge_id": "plant-a", "fields": {}})


def opened_kind(c, sealed, fmt):
    return E.unseal(sealed, c["signer"].bundle_public()["key"], fmt)


def test_an_ended_notice_needs_the_records_to_end_the_edge(core):
    with pytest.raises(SignerRefused, match="not ended"):
        core["signer"].seal_edge({"kind": "ended", "edge_id": "plant-a", "fields": {}})


def test_an_email_answer_is_only_for_a_live_lease_and_comes_from_the_identity_map(core):
    s = core["signer"]
    with pytest.raises(SignerRefused, match="no lease"):
        s.seal_edge({"kind": "email", "edge_id": "plant-a", "fields": {"lease_id": "L-nope", "nonce": "n"},
                     "identity_map": idmap(core)})
    lease = next(x for x in opened(core, seal(core))["leases"] if x["person"] == core["a"]["ann"])
    sealed_map = M.seal(core["reconciler"], core["realm"], 1, datetime.now(timezone.utc) + timedelta(seconds=1),
                        {core["a"]["ann"]: "ann"}, {core["a"]["ann"]: ("ann" + "@example.org")})
    m = opened_kind(core, s.seal_edge({"kind": "email", "edge_id": "plant-a",
                                       "fields": {"lease_id": lease["lease_id"], "nonce": "n-1"},
                                       "identity_map": sealed_map}), E.EMAIL_FORMAT)
    assert m["email"] == ("ann" + "@example.org") and m["person"] == core["a"]["ann"]


def test_an_acknowledgement_is_of_what_the_signer_holds_never_what_the_desk_names(core):
    """0.29 review S2: no kind lets the desk name an evidence head or an escrow status; the signer continues the chain
    it holds and refuses an entry that does not follow it."""
    s = core["signer"]
    for kind, fields in (("evidence_ack", {"up_to_seq": 3, "head": "a" * 64}),
                         ("escrow_status", {"item_id": "BG-1", "sha256": "a" * 64, "confirmed": True,
                                            "custodians_confirmed": 2})):
        with pytest.raises(SignerRefused):
            s.seal_edge({"kind": kind, "edge_id": "plant-a", "fields": fields})
    e1 = {"seq": 1, "prev": "0" * 64, "sha256": "a" * 64, "size": 1, "session": "S-1", "at": "2026-11-07T10:00:00Z"}
    m = opened_kind(core, s.seal_edge({"kind": "evidence", "edge_id": "plant-a", "fields": {"entries": [e1]}}),
                    "kc-edge-evidence-ack-v1")
    assert m["up_to_seq"] == 1 and m["head"] == E.sha256(E.canonical(e1)) and "at" in m
    with pytest.raises(SignerRefused, match="holds this edge's evidence to seq 1"):
        s.seal_edge({"kind": "evidence", "edge_id": "plant-a", "fields": {"entries": [{**e1, "seq": 5, "prev": "b" * 64}]}})
    with pytest.raises(SignerRefused, match="no such kind"):
        s.seal_edge({"kind": "bundle", "edge_id": "plant-a", "fields": {}})


def test_a_signer_on_signed_yaml_cuts_from_the_revision_it_signed(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    try:
        Store(tmp_path / "desk", None, FIXTURES / "records.yaml", signer=signer).close()
        head = signer.edges()._head()
        assert head["revision"] >= 1 and len(head["head"]) == 64
        with pytest.raises(SignerRefused, match="no enrolled edge"):
            signer.seal_edge({"kind": "time", "edge_id": "plant-a", "fields": {"nonce": "n"}})
    finally:
        signer.close()


def test_without_a_pinned_key_and_without_a_map_no_lease_names_an_account(core):
    core["signer"].configure_identity(None)
    body = opened(core, seal(core, identity_map=None))
    assert body["leases"] and all(x["username"] is None for x in body["leases"])


def test_an_upgraded_desk_with_only_usernames_says_once_that_leases_name_no_account(tmp_path):
    """0.28 to 0.29: the reconciler's usernames.json is there, its sealed map is not: bundles still flow (revocations
    reach the edge), no lease names an account, and the edge gets one incident with the next step."""
    import json
    from test_edges import enrol, edge_desk, INGRID, W
    state = tmp_path / "broker"
    state.mkdir()
    (state / "usernames.json").write_text(json.dumps({"idp:7c1f-ann": "ann"}), encoding="utf-8")
    desk = edge_desk(tmp_path, broker_state=state)
    desk.approve(W(INGRID), enrol(desk)["change_id"])
    for _ in range(2):
        desk.edge_bundle("plant-a")
    kinds = [i["kind"] for i in desk.edge_store.incidents("plant-a")]
    assert kinds.count("identity_map_missing") == 1


def test_a_bundle_key_rollover_needs_each_edges_officer(core):
    """#41 F6: a rollover was signed by the old bundle key alone, so whoever held it moved every edge to their own.
    Now each live edge's officer co-signs (kc-edge-key-rollover-v2), the signer checks that against the officer key in
    its records, and an edge accepts only both signatures over its own edge and pinned key."""
    s = core["signer"]
    old = s.bundle_public()["key"]
    sts = s.rollover_begin()["statements"]
    assert len(sts) == 1
    with pytest.raises(SignerRefused, match="does not hold"):
        s.rollover_finish(sts)                                         # not yet co-signed by the officer
    signed = [E.cosign(core["officer"], st, E.ROLLOVER_FORMAT_V2) for st in sts]
    out = s.rollover_finish(signed)
    assert out["old"] == old and out["new"] != old and out["edges"] == ["plant-a"]
    assert s.bundle_public()["key"] == out["new"]                      # bundles are sealed with the new key now
    pins = {"edge": "plant-a", "bundle_key": old, "officer_key": E.public_hex(core["officer"])}
    rollover = s.bundle_public("plant-a")["rollover"]
    assert E.accept_rollover(rollover, pins) == out["new"]
    with pytest.raises(ValueError):
        E.accept_rollover(rollover, {**pins, "edge": "plant-b"})       # never for another edge
    with pytest.raises(ValueError, match="signed by exactly"):
        E.accept_rollover(sts[0], pins)                                # the old key alone
    v1 = E.seal(Ed25519PrivateKey.generate(), {"new_key": out["new"]}, E.ROLLOVER_FORMAT)
    with pytest.raises(ValueError, match="old key alone"):
        E.accept_rollover(v1, pins)


def test_the_desks_attestation_claim_is_never_taken(core):
    """0.29 review S12: a taken-over desk claimed "assured" and got visit leases into a basic edge's bundle. The
    signer now judges the quote itself; without one, or for an edge enrolled without a TPM, the edge is basic."""
    seal(core, attested="assured")
    assert core["signer"].edges()._read("attested.json")["plant-a"] == "basic"


def test_an_address_is_only_for_a_lease_a_bundle_would_carry_now(core, monkeypatch):
    """0.29 review S11: the address path took any lease inside the ceiling; a lease a cross-edge exclusion holds on
    another edge (or a class without a horizon) is dropped from bundles, and now gets no address either."""
    from keyclerk import edge_grants
    s = core["signer"]
    lease = next(x for x in opened(core, seal(core))["leases"] if x["person"] == core["a"]["ann"])
    sealer = s.edges()
    real = sealer._records
    monkeypatch.setattr(sealer, "_records", lambda: {**real(), "edge_exclusions": [{"held": "elsewhere"}]})
    monkeypatch.setattr(edge_grants, "excluded", lambda doc, e, now, horizons: {lease["lease_id"]: "held on plant-b"})
    with pytest.raises(SignerRefused, match="no lease by that id"):
        s.seal_edge({"kind": "email", "edge_id": "plant-a", "fields": {"lease_id": lease["lease_id"], "nonce": "n-2"},
                     "identity_map": idmap(core)})


def test_a_new_key_file_is_whole_and_one_key_however_many_threads_make_it(tmp_path):
    """0.29 review S9: a key is written whole and synced under a temporary name and then linked into place, so a
    crash leaves no half key, and two threads making it at once end up with the one key."""
    import threading
    f, got, errors = tmp_path / "bundle.key", [], []

    def make():
        try:
            got.append(E.public_hex(E.load_or_make_key(f, allow_create=True)))
        except Exception as e:   # noqa: BLE001 - every thread's failure fails the test
            errors.append(e)
    ts = [threading.Thread(target=make) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errors == [] and len(got) == 8 and len(set(got)) == 1 and len(f.read_text(encoding="utf-8").strip()) == 64
    assert not list(tmp_path.glob("*.new"))


def test_a_rollover_reaches_both_ha_nodes_from_one_next_key(core, tmp_path):
    """#41 F6 in HA mode: the nodes share one bundle key, so the next key is made once and each node begins from it;
    the officer co-signs one node's statements, and both nodes finish with them on the same new key."""
    from keyclerk.edge_sealer import EdgeRefused, EdgeSealer
    one = core["signer"].edges()
    two = EdgeSealer(tmp_path / "node2", one.source, one.clock)
    two.import_key(one.dir / "bundle.key")
    one.ha = two.ha = True
    with pytest.raises(EdgeRefused, match="begin on every node with --next"):
        one.rollover_begin()
    nxt = tmp_path / "next.key"
    E.load_or_make_key(nxt, allow_create=True)
    sts = one.rollover_begin(nxt)
    two.rollover_begin(nxt)
    with pytest.raises(EdgeRefused, match="another next key"):
        other = tmp_path / "other.key"
        E.load_or_make_key(other, allow_create=True)
        two.rollover_begin(other)
    signed = [E.cosign(core["officer"], st, E.ROLLOVER_FORMAT_V2) for st in sts]
    a, b = two.rollover_finish(signed), one.rollover_finish(signed)      # the standby first, then the active
    assert a["new"] == b["new"] == E.public_hex(E.load_or_make_key(nxt, allow_create=False)) != a["old"]
    assert E.public_hex(one.key) == E.public_hex(two.key)


def test_the_rollover_ceremony_runs_from_the_command_line(core, tmp_path):
    """#41 F6: begin and finish are an operator's commands on the stopped signer (python -m keyclerk.signer rollover)."""
    import json

    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    from keyclerk import signer as S
    s = core["signer"]
    keyfile = tmp_path / "records.key"
    keyfile.write_text(s.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    state, old = str(s.state), s.bundle_public()["key"]
    s.close()
    cfg = str(FIXTURES / "config.yaml")
    out = tmp_path / "statements.json"
    assert S.main(["rollover", "begin", "--key", str(keyfile), "--state", state, "--config", cfg, "--out", str(out)]) == 0
    signed = [E.cosign(core["officer"], st, E.ROLLOVER_FORMAT_V2) for st in json.loads(out.read_text())]
    (tmp_path / "cosigned.json").write_text(json.dumps(signed))
    assert S.main(["rollover", "finish", "--key", str(keyfile), "--state", state, "--config", cfg, "--statements",
                   str(tmp_path / "cosigned.json")]) == 0
    again = S.Signer(s.key, s.state)
    try:
        assert again.bundle_public()["key"] != old
    finally:
        again.close()


def test_d3_escrow_and_its_confirmations_live_in_the_log_so_either_node_answers(core, tmp_path):
    """0.29 D3: with a change log, the signer records each escrow and each custodian's confirmation as its own
    records; a second HA node, reading the same log, answers the status the first one counted."""
    import time

    from test_edge_two_node_end_unlock import _Proofs

    from keyclerk import relay as R
    from keyclerk.edge_sealer import EdgeSealer
    desk, w, a, s = core["desk"], core["w"], core["a"], core["signer"]
    keys = {}
    for who in ("finn", "gina"):
        priv, pub = R.person_key_from_prf(bytes([0x30 + len(keys)]) * 32)
        r = desk.propose(w(who), {"action": "enrol_person_key", "public_key": R.b64e(pub), "user_verification": True})
        assert desk.approve(w("ingrid"), r["change_id"])["outcome"] == "applied"
        keys[who] = (next(k["key_id"] for k in desk.store.load()["person_keys"] if k["anchor"] == a[who]), pub)
    ctx = "escrow:plc:BG-9"
    envs = [{"key_id": keys[x][0], "envelope": R.encrypt(R.b64e(keys[x][1]), b"half", ctx)} for x in ("finn", "gina")]
    s.seal_edge({"kind": "escrow", "edge_id": "plant-a", "fields": {"system": "plc", "item_id": "BG-9",
                                                                     "envelopes": envs}})
    doc = s.edges()._records()
    assert [x["item_id"] for x in doc.get("edge_escrows", [])] == ["BG-9"]
    s.proofs = _Proofs()
    from keyclerk.approvals import escrow_statement
    item = s.edges()._escrow_item("plant-a", {"item_id": "BG-9"})
    for who in ("finn", "gina"):
        st = escrow_statement(core["realm"], "plant-a", "BG-9", item["sha256"], a[who])
        s.seal_edge({"kind": "escrow_confirm", "edge_id": "plant-a",
                     "fields": {"item_id": "BG-9", "custodian": a[who], "proof": f"signed:{st}:{a[who]}#{time.time()}"}})
    other = EdgeSealer(tmp_path / "node2", s.edges().source, s.edges().clock)
    other.import_key(s.edges().dir / "bundle.key")
    other.record = s.record_own
    m = E.unseal(other.seal("escrow_status", "plant-a", {"item_id": "BG-9"}), s.bundle_public()["key"],
                 "kc-edge-escrow-status-v1")
    assert m["confirmed"] is True and m["custodians_confirmed"] == 2


def test_d3_the_signers_own_records_never_come_from_a_desk(core):
    s = core["signer"]
    rec = {"activation_id": "plant-a.ab", "edge": "plant-a", "ak_name": "ab", "at": "2026-11-07T10:00:00Z"}
    s.record_own([{"op": "put", "kind": "edge_activations", "key": rec["activation_id"], "record": rec}], "edge_activation")
    assert s.edges()._activated(s.edges()._records(), "plant-a", "ab")
    store = s.replica
    h = store.head()
    with pytest.raises(SignerRefused, match="the checking signer's own records"):
        s.propose({"size": store.size(), "head": h.hex()},
                  {"ops": [{"op": "put", "kind": "edge_activations", "key": "plant-a.cd",
                            "record": {**rec, "activation_id": "plant-a.cd", "ak_name": "cd"}}],
                   "entry": {"change_id": "C-0123456789ab", "action": "x", "actor": None, "outcome": "applied",
                             "records": {}}}, [])


def test_issue_52_the_bundle_says_why_a_lease_was_dropped(core):
    """Edge protocol 1.6: what the signer left out reaches the edge, signed, so the edge can say why it has no lease.
    A ceiling of one hour drops every day-long membership's lease; a refused ceiling is a reason for the whole edge."""
    got = seal(core, ceiling=E.seal_ceiling(core["officer"], {**E.opened(ceiling(core)), "max_lease_hours": 1}))
    body = opened(core, got)
    assert got["dropped"] and body["dropped"] == E.bundle_dropped(got["dropped"])
    assert all(isinstance(d["why"], list) and d["why"] for d in body["dropped"])
    other = dict(core, officer=Ed25519PrivateKey.generate())
    body = opened(core, seal(core, serial=2, ceiling=ceiling(other)))
    assert any(d["lease_id"] is None and "ceiling is refused" in d["why"][0] for d in body["dropped"])


def test_a_bundle_bounds_what_it_says_was_dropped():
    many = [{"lease_id": f"L-{i}", "why": ["x" * 500] * 9} for i in range(300)]
    out = E.bundle_dropped(many)
    assert len(out) == E.DROPPED_MAX and all(len(d["why"]) == E.DROPPED_WHY_MAX for d in out)
    assert all(len(w) == E.DROPPED_TEXT_MAX for d in out for w in d["why"]) and not E.dropped_errors(out)


def test_the_long_poll_digest_counts_dropped_as_content():
    """Edge protocol 1.6 with 1.4 agents, which ignore dropped: the desk's content digest and an agent's both hash
    every member but serial, issued, format and key_id, so a change in dropped is a content change on both sides."""
    from datetime import datetime, timezone
    key = Ed25519PrivateKey.generate()
    t = datetime(2026, 11, 7, tzinfo=timezone.utc)
    pol = {"modules": {}, "release": None, "entrypoints": []}
    a = E.build_bundle("edge-a", 1, t, {"low": 1}, [], [], [], None, pol, key)
    b = E.build_bundle("edge-a", 2, t, {"low": 1}, [], [], [], None, pol, key, dropped=[])
    c = E.build_bundle("edge-a", 3, t, {"low": 1}, [], [], [], None, pol, key,
                       dropped=[{"lease_id": "L-1", "why": ["longer than the ceiling's longest lease"]}])
    assert len({E.bundle_digest(a), E.bundle_digest(b), E.bundle_digest(c)}) == 3
