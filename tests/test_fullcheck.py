"""Decision 0022 S4: the background full check on a snapshot, freezing on a verified integrity violation and
alarming on anything incomplete or time-born (a transient failure must not halt signing)."""
import json
from collections import namedtuple
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import fullcheck, metrics, scope
from keyclerk.desk import Store
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import link as L

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def signer(tmp_path):
    key = Ed25519PrivateKey.generate()
    s = Signer(key, tmp_path / "state")
    Store(tmp_path / "desk", None, FIXTURES / "records.yaml", signer=s).close()
    s.migrate()
    yield s
    s.close()


def _sneak(s, ops):
    """A link the replica keeps without the signer's checks (what a reach bug would have let through)."""
    r = s.replica
    sealed = L.seal_link(s.key, r.realm, r.size(), r.head().hex(), 1, "2026-10-24T12:00:00Z", ops, {"action": "test"})
    r.append(sealed)
    r.add_checkpoint(L.seal_checkpoint(s.key, r.realm, r.size(), r.root(), r.head(), 1, "2026-10-24T12:00:00Z"))


def _bad_membership(s):
    m = next(rec for _, rec in s.replica.scan("memberships"))
    return [{"op": "put", "kind": "memberships", "key": "M-sneaked", "record": {**m, "membership_id": "M-sneaked",
                                                                                 "group": "no-such-group"}}]


def test_a_clean_replica_passes_and_ends_the_full_per_change_period(signer):
    assert signer.config_pending
    first = signer.background_check()
    assert first.ok and first.frozen is None and not signer.config_pending
    assert (signer.state / "fullcheck-previous.sqlite").exists()
    second = signer.background_check()                     # now against the previous snapshot
    assert second.ok and second.frozen is None


def test_an_error_outside_every_reach_freezes_signing_across_a_restart(signer, monkeypatch):
    signer.background_check()
    _sneak(signer, _bad_membership(signer))
    monkeypatch.setattr(scope, "reach", lambda old, new, ops: set())        # a reach bug: nothing reached
    result = signer.background_check()
    assert result.frozen and "outside every change's reach" in result.frozen
    assert signer.broken and "frozen" in signer.broken
    with pytest.raises(SignerRefused, match="signing is frozen"):
        signer.propose({"size": signer.replica.size(), "head": signer.replica.head().hex()}, {"ops": [], "entry": {}}, [])
    key, state = signer.key, signer.state
    signer.close()
    again = Signer(key, state)
    assert again.broken and "keyclerk.signer resume" in again.broken
    again.close()


def test_an_error_inside_the_reach_is_time_born_an_alarm_never_a_freeze(signer):
    signer.background_check()
    _sneak(signer, _bad_membership(signer))                 # inside its own change's reach: accepted then, wrong now
    before = metrics._counters.get(("keyclerk_check_alarms_total", (("kind", "time_born"),)), 0)
    result = signer.background_check()
    assert result.frozen is None and any(a.startswith("time-born") for a in result.alarms)
    assert metrics._counters[("keyclerk_check_alarms_total", (("kind", "time_born"),))] == before + 1
    assert signer.broken is None


def test_a_scoped_judgement_that_differs_from_the_full_one_freezes(signer, monkeypatch):
    _sneak(signer, _bad_membership(signer))
    monkeypatch.setattr(scope, "scoped_errors", lambda doc, reach: [])
    result = signer.background_check()
    assert result.frozen and "differs from the full check" in result.frozen


def test_an_incomplete_run_alarms_and_retries_but_never_freezes(signer, monkeypatch):
    calls = []

    def boom(*a):
        calls.append(1)
        raise MemoryError("out of memory")
    monkeypatch.setattr(fullcheck, "_findings", boom)
    result = signer.background_check()
    assert result.frozen is None and result.alarms[0].startswith("incomplete") and signer.broken is None
    assert signer.config_pending                            # not passed: changes stay judged in full


def test_without_the_space_for_two_snapshots_it_refuses_to_start_saying_why(signer, monkeypatch):
    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(fullcheck.shutil, "disk_usage", lambda p: Usage(10, 10, 0))
    with pytest.raises(fullcheck.NoSpace, match="two snapshots of the replica's size.*free that much space"):
        signer.background_check()


def _frozen_by_a_reach_bug(signer, monkeypatch):
    signer.background_check()                              # a baseline that passed
    _sneak(signer, _bad_membership(signer))
    monkeypatch.setattr(scope, "reach", lambda old, new, ops: set())
    result = signer.background_check()
    assert result.frozen
    return result


def test_an_incomplete_run_keeps_the_baseline_so_an_out_of_reach_error_still_freezes(signer, monkeypatch):
    """The review's point 1 (i): one exception at the wrong moment must not launder an error into the baseline."""
    signer.background_check()
    _sneak(signer, _bad_membership(signer))
    monkeypatch.setattr(scope, "reach", lambda old, new, ops: set())
    real = fullcheck._findings
    monkeypatch.setattr(fullcheck, "_findings", lambda *a: (_ for _ in ()).throw(MemoryError("now")))
    assert signer.background_check().alarms[0].startswith("incomplete")
    monkeypatch.setattr(fullcheck, "_findings", real)
    result = signer.background_check()
    assert result.frozen and "outside every change's reach" in result.frozen


def test_a_resume_without_accepting_the_state_freezes_again_and_one_that_accepts_it_does_not(signer, monkeypatch):
    """The review's point 1 (ii) and point 2: the frozen state never becomes the baseline unless a resume says so."""
    _frozen_by_a_reach_bug(signer, monkeypatch)
    line = signer.resume("operator-1", "investigated: a test of the freeze", accept_baseline=False)
    assert line["accept_baseline"] is False and line["by"] == "operator-1" and "outside every change" in line["ends"]
    again = signer.background_check()
    assert again.frozen                                    # nothing was fixed: the same error is new again
    signer.resume("operator-1", "accepted: the error is known and tracked", accept_baseline=True)
    assert signer.background_check().frozen is None and signer.broken is None
    ops = [json.loads(x)["op"] for x in (signer.state / "audit.jsonl").read_text().splitlines()]
    assert ops == ["freeze", "resume", "freeze", "resume"]
    assert signer.verify_audit() is None                   # every line signed and chained


def test_removing_the_freeze_file_by_hand_resumes_nothing(signer, monkeypatch):
    _frozen_by_a_reach_bug(signer, monkeypatch)
    (signer.state / "frozen.json").unlink()
    key, state = signer.key, signer.state
    signer.close()
    again = Signer(key, state)
    assert again.broken and "signing is frozen" in again.broken and "removing frozen.json does not resume" in again.broken
    again.close()


def test_there_is_nothing_to_resume_on_a_signer_that_is_not_frozen(signer):
    with pytest.raises(SignerRefused, match="nothing to resume"):
        signer.resume("operator-1", "no freeze to end here", False)


def test_a_resume_needs_a_name_a_reason_and_a_terminal(signer, monkeypatch, capsys):
    from keyclerk import signer as S
    _frozen_by_a_reach_bug(signer, monkeypatch)
    with pytest.raises(SignerRefused, match="names who resumes"):
        signer.resume("", "short", False)
    monkeypatch.setattr(S.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit, match="a resume runs at the signer's terminal"):
        S.main(["resume", "--key", "k", "--state", str(signer.state), "--config", "c", "--by", "x", "--reason", "y" * 10])


def test_a_frozen_marker_names_why_and_how_to_resume(tmp_path):
    fullcheck.freeze(tmp_path, "a test")
    v = json.loads((tmp_path / "frozen.json").read_text())
    msg = fullcheck.frozen_message(v["at"], v["why"])
    assert "a test" in msg and "keyclerk.signer resume" in msg


def test_an_engine_that_tightens_the_schema_judges_in_full_and_alarms_needs_migration_never_freezes(signer, monkeypatch):
    """The review's condition for checking the schema over touched records only: an upgrade whose schema the old state
    fails is an upgrade, not an integrity violation."""
    from keyclerk import config
    assert signer.background_check().ok and not signer.config_pending
    key, state = signer.key, signer.state
    signer.close()
    real = config.schema

    def tighter(name):
        s = real(name)
        if name == "records":
            s = {**s, "properties": {**s["properties"], "realm": {**s["properties"]["realm"], "maxLength": 3}}}
        return s
    monkeypatch.setattr(config, "schema", tighter)
    upgraded = Signer(key, state)
    try:
        assert upgraded.config_pending and upgraded.broken is None and upgraded.not_ready
        r = upgraded.replica
        with pytest.raises(SignerRefused, match="Run the records migration"):   # nothing is signed unjudged
            upgraded.propose({"size": r.size(), "head": r.head().hex()}, {"ops": [], "entry": {"action": "test"}}, [])
        result = upgraded.background_check()
        assert result.frozen is None and upgraded.broken is None
        assert any(a.startswith("needs migration") and "roll the engine back" in a for a in result.alarms)
        assert upgraded.config_pending                     # still in full until it is migrated
    finally:
        upgraded.close()


def test_under_the_same_schema_a_record_that_fails_it_is_a_violation(signer, monkeypatch):
    assert signer.background_check().ok
    m = next(rec for _, rec in signer.replica.scan("memberships"))
    _sneak(signer, [{"op": "put", "kind": "memberships", "key": m["membership_id"],
                     "record": {**m, "end": "not a time"}}])
    result = signer.background_check()
    assert result.frozen and "fail the records schema they were checked against" in result.frozen


def test_a_working_set_that_misses_a_record_freezes(signer, monkeypatch):
    """The background check judges a sample of subjects on the working set against the full check: a loader gap
    (here: the delegations left out) shows as a difference, verified by the rerun, and freezes."""
    from keyclerk.store import working
    assert signer.background_check().ok
    monkeypatch.setattr(fullcheck, "SAMPLE", 1000)
    real = working.working_doc
    monkeypatch.setattr(working, "working_doc", lambda ix, reach, rev: {**real(ix, reach, rev), "delegations": []})
    result = signer.background_check()
    assert result.frozen and "the working set judges" in result.frozen


def _lower_proof_cap(monkeypatch, cap):
    from keyclerk import config
    real = config.schema

    def capped(name):
        s = real(name)
        if name == "records":
            props = dict(s["properties"])
            props["approval_proofs"] = {**props["approval_proofs"], "maxItems": cap}
            s = {**s, "properties": props}
        return s
    monkeypatch.setattr(config, "schema", capped)


def test_a_replica_past_the_whole_document_proof_cap_passes_the_background_check(signer, monkeypatch):
    """The review's call on maxItems: a whole-document cap bounds one YAML file read whole; a replica keeps records one
    per row and bounds each change instead, so a replica past it is fine. (The cap is 100,000 in the schema; it is
    lowered here to 1 rather than writing 100,000 proofs.) The YAML path keeps the cap."""
    from keyclerk import records
    from keyclerk.store import replay as RP
    from keyclerk import anchors as A
    assert signer.background_check().ok
    ann = A.inward(signer.replica, "idp:7c1f-ann")          # the log names her by her internal anchor (decision 0028)
    for i in range(2):
        token = f"eyJ.token-{i}.sig"
        p = L.proof_record({"records": ["M-example-0001"], "by": ann, "token": token})
        signer.propose({"size": signer.replica.size(), "head": signer.replica.head().hex()},
                       {"ops": [{"op": "put", "kind": "approval_proofs", "key": p["sha256"], "record": p}], "entry": {}},
                       [[p["sha256"], token]])
    _lower_proof_cap(monkeypatch, 1)
    doc = RP.records(signer.replica)
    assert any("approval_proofs" in e for e in records.validate(doc))           # the YAML path: over the cap
    assert records.validate(doc, log_backed=True) == []                         # one record per row: no cap
    result = signer.background_check()
    assert result.frozen is None and not [a for a in result.alarms if "needs migration" in a]


def test_a_change_past_the_per_change_cap_is_refused(signer):
    r = signer.replica
    ops = [{"op": "put", "kind": "groups", "key": f"g-{i:04d}", "record": {"group_id": f"g-{i:04d}", "parent": "all",
                                                                           "max_risk": "low"}} for i in range(501)]
    with pytest.raises(SignerRefused, match="more than 500 records of groups: split it"):
        signer.propose({"size": r.size(), "head": r.head().hex()}, {"ops": ops, "entry": {}}, [])


def test_the_full_path_fails_closed_on_records_the_schema_refuses(signer, monkeypatch):
    """The full check stops at schema errors; old and new would share them and nothing else would be judged. So a
    signer judging in full refuses rather than sign unjudged (after an upgrade that tightens the schema)."""
    from keyclerk import config
    real = config.schema
    monkeypatch.setattr(config, "schema", lambda n: {**real(n), "properties": {
        **real(n)["properties"], "realm": {**real(n)["properties"]["realm"], "maxLength": 3}}} if n == "records" else real(n))
    signer.config_pending = True
    r = signer.replica
    with pytest.raises(SignerRefused, match="cannot judge a change on them.*migration.*roll the engine back"):
        signer.propose({"size": r.size(), "head": r.head().hex()}, {"ops": [], "entry": {}}, [])


def test_records_the_schema_refuses_make_the_signer_not_ready_with_the_reason_and_refuse_changes(signer, monkeypatch,
                                                                                                tmp_path):
    """The review's addition: validated at start and after each background run; the signer still starts and answers
    (resume, health, the background check), /readyz says not ready with the reason, a change is refused."""
    import threading
    from keyclerk import config, health
    from keyclerk.signer import SignerClient, serve
    key, state = signer.key, signer.state
    signer.close()
    real = config.schema
    monkeypatch.setattr(config, "schema", lambda n: {**real(n), "properties": {
        **real(n)["properties"], "realm": {**real(n)["properties"]["realm"], "maxLength": 3}}} if n == "records" else real(n))
    before = metrics._counters.get(("keyclerk_check_alarms_total", (("kind", "needs_migration"),)), 0)
    started = Signer(key, state)
    srv = serve(started, "tcp:127.0.0.1:0", "t0ken-for-tests")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert started.broken is None and started.not_ready and "roll the engine back" in started.not_ready
        assert metrics._counters[("keyclerk_check_alarms_total", (("kind", "needs_migration"),))] == before + 1
        tok = tmp_path / "token"
        tok.write_text("t0ken-for-tests", encoding="utf-8")
        client = SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(tok))

        class Desk:                               # a desk whose own checks pass: only the signer's readiness matters
            class store:
                load = staticmethod(lambda: {})
                verify_log = staticmethod(lambda: [])
        detail = health.Readiness(Desk(), signer=client).detail()
        assert detail["ready"] is False
        assert "records migration" in detail["checks"]["signer"]["why"]
        r = started.replica
        with pytest.raises(SignerRefused, match="Run the records migration"):
            client.propose({"size": r.size(), "head": r.head().hex()}, {"ops": [], "entry": {}})
    finally:
        srv.shutdown()
        srv.server_close()
        started.close()


def test_a_changed_configuration_whose_records_still_meet_the_schema_is_judged_in_full(signer, monkeypatch):
    assert signer.background_check().ok and not signer.config_pending
    key, state = signer.key, signer.state
    signer.close()
    monkeypatch.setattr(Signer, "_config_sha", classmethod(lambda cls: "another configuration"))
    again = Signer(key, state)
    try:
        assert again.config_pending and again.not_ready is None
        before = metrics._counters.get(("keyclerk_check_fallback_total", (("reason", "config"),)), 0)
        r = again.replica
        again.propose({"size": r.size(), "head": r.head().hex()}, {"ops": [], "entry": {"action": "test"}}, [])
        assert metrics._counters[("keyclerk_check_fallback_total", (("reason", "config"),))] == before + 1
    finally:
        again.close()
