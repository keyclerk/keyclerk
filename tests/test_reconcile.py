# SPDX-License-Identifier: EUPL-1.2
"""The reconciler's contract: nothing unchecked, unsigned or history-rewriting is applied; removals are capped; failed
logouts are retried; dry run is the default; every run is logged; one writer at a time."""
import copy
import json
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from keyclerk import reconcile as Rc, records
from keyclerk.guard import InputRejected
from keyclerk.connectors.contract import Capabilities, MembershipTarget

FIXTURES = Path(__file__).resolve().parent / "fixtures"
AT = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


class Broker(MembershipTarget):
    """An in-memory broker: memberships, a flaky logout, findings."""

    def __init__(self, have=(), logout_fails=False):
        super().__init__(name="fake-broker", caps=Capabilities("target", ("membership",)))
        self.have, self.logout_fails, self.findings, self.logged_out = set(have), logout_fails, [], []
        self.managed = ("/grants/", "/leases/", "/groups/")

    def read_full(self):
        return set(self.have)

    def _apply(self, plan):
        done = {"added": [], "removed": [], "failed": [], "logout_pending": [], "missing_people": []}
        for g, a in plan["remove"]:
            self.have.discard((g, a))
            done["removed"].append((g, a))
            if self.logout_fails:
                done["logout_pending"].append(f"0000aaaa-{len(done['removed']):04d}")
        for g, a in plan["add"]:
            self.have.add((g, a))
            done["added"].append((g, a))
        return done

    def logout(self, uid):
        if self.logout_fails:
            raise RuntimeError("broker down")
        self.logged_out.append(uid)


def args(tmp_path, records_file, **kw):
    a = dict(config=str(FIXTURES / "config.yaml"), records=str(records_file), keycloak="http://localhost:1",
             realm="example", client="keyclerk-reconciler", secret_file="x", reader_client=None, reader_secret_file=None,
             state=str(tmp_path / "state"), signing_key=None, allow_unsigned=True, trust=None, interval=60, once=True,
             apply=True, config_hash="test")
    a.update(kw)
    return types.SimpleNamespace(**a)


def write(tmp_path, doc, name="records.yaml"):
    f = tmp_path / name
    f.write_text(yaml.safe_dump(json.loads(json.dumps(doc, default=str)), sort_keys=False), encoding="utf-8")
    return f


def doc():
    return copy.deepcopy(records.load(FIXTURES / "records.yaml"))


def test_a_clean_revision_is_applied_and_logged(tmp_path):
    b = Broker()
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert run["applied"] and not run.get("refused") and len(b.have) == run["desired"] > 0
    log = (tmp_path / "state" / "runs.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(log) == 1 and json.loads(log[0])["records_sha256"]


def test_records_that_fail_a_check_are_refused_and_nothing_changes(tmp_path):
    d = doc()
    d["grants"][0]["approved_by"] = [d["grants"][0]["requested_by"]]          # self-approval
    b = Broker(have={("/grants/x", "idp:keep")})
    run = Rc.run_once(args(tmp_path, write(tmp_path, d)), AT, b)
    assert run["refused"].startswith("records refused") and b.have == {("/grants/x", "idp:keep")}


def test_unsigned_records_are_refused_unless_allowed_and_a_bad_signature_is_refused(tmp_path):
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml", allow_unsigned=False), AT, Broker())
    assert "unsigned" in run["refused"]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    rec = tmp_path / "records.yaml"
    rec.write_bytes((FIXTURES / "records.yaml").read_bytes())
    pub = tmp_path / "key.pub"
    pub.write_text(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), encoding="utf-8")
    (tmp_path / "records.yaml.sig").write_text(key.sign(rec.read_bytes()).hex(), encoding="utf-8")
    ok = Rc.run_once(args(tmp_path, rec, allow_unsigned=False, signing_key=str(pub)), AT, Broker())
    assert ok["applied"]
    rec.write_bytes(rec.read_bytes() + b"\n# tampered\n")
    bad = Rc.run_once(args(tmp_path, rec, allow_unsigned=False, signing_key=str(pub)), AT, Broker())
    assert "signature" in bad["refused"]


def test_a_revision_that_drops_a_revocation_is_refused(tmp_path):
    Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, Broker())
    d = doc()
    d["revocations"] = []
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r2.yaml")), AT, Broker())
    assert "history" in run["refused"]


def test_a_revision_that_takes_much_away_waits_for_an_override_but_intruders_always_go(tmp_path):
    b = Broker()
    first = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert first["applied"] and first["desired"] > 4
    d = doc()
    root = d["root"]["holders"][0]["anchor"]
    d.setdefault("admin_revocations", []).extend(
        {"id": m["membership_id"], "at": AT - timedelta(minutes=1), "by": root, "mode": "retire", "reason": "reorganisation"}
        for m in d["memberships"])                                          # every membership retired at once
    b.have |= {(f"/grants/planted-{i}", f"idp:p{i}") for i in range(80)}          # helpdesk adds 80 by hand
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r2.yaml")), AT, b)
    assert "exceed the cap" in run["refused"] and not run["applied"]
    assert run["intrusions_removed"] == 80 and not any(g.startswith("/grants/planted") for g, _ in b.have)
    assert len(b.have) == first["desired"]                                    # the lawful removals wait
    (tmp_path / "state" / "override-removal-cap").write_text(run["plan_sha256"], encoding="utf-8")
    run2 = Rc.run_once(args(tmp_path, write(tmp_path, d, "r2.yaml")), AT, b)
    assert run2["applied"] and len(b.have) == run2["desired"]


def test_a_refused_run_never_releases_the_lock_it_does_not_hold(tmp_path):
    st = Rc.State(tmp_path / "state", Rc.timedelta(seconds=600))
    st.lock()
    other = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, Broker())
    assert "writer lock" in other["refused"] and (tmp_path / "state" / "writer.lock").exists()
    st.unlock()
    assert not (tmp_path / "state" / "writer.lock").exists()


def test_an_expired_lock_is_taken_over_and_the_old_owner_cannot_renew_it(tmp_path):
    old = Rc.State(tmp_path / "state", Rc.timedelta(seconds=-1))             # a lease already over
    old.lock()
    new = Rc.State(tmp_path / "state", Rc.timedelta(seconds=600))
    new.lock()
    with pytest.raises(Rc.Refused, match="lost"):
        old.renew()
    old.unlock()
    assert (tmp_path / "state" / "writer.lock").exists()                      # still the new owner's
    new.unlock()


def test_a_failed_logout_is_queued_retried_and_alerted(tmp_path):
    b = Broker(have={("/grants/gone", "idp:p1")}, logout_fails=True)
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert run["logout_queue"] == 1
    later = datetime(2026, 10, 22, 13, 0, tzinfo=timezone.utc)
    run2 = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), later, b)
    assert run2["logout_queue"] == 1 and "logouts pending" in run2["alert"]
    b.logout_fails = False
    run3 = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), later, b)
    assert run3["logout_queue"] == 0 and b.logged_out


def test_dry_run_is_the_default_and_changes_nothing(tmp_path):
    b = Broker()
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml", apply=False), AT, b)
    assert not run["applied"] and run["add"] and not b.have


def test_one_writer_at_a_time(tmp_path):
    st = Rc.State(tmp_path / "state", Rc.timedelta(seconds=600))
    (tmp_path / "state" / "writer.lock").write_text(json.dumps({"pid": -1, "until": 9e12}), encoding="utf-8")
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, Broker())
    assert "writer lock" in run["refused"]
    assert st.path.exists()


def test_require_trust_keeps_every_group_member_dormant_without_trust_input(tmp_path):
    from keyclerk import config
    cfg = copy.deepcopy(config.current())
    cfg["risk_port"]["require_trust"] = True
    config.configure(cfg)
    try:
        want = Rc.desired(doc(), AT)
        assert not any(g.startswith("/groups/") for g, _ in want)        # absent trust is the strictest value
        assert any(g.startswith("/grants/") for g, _ in want)             # grants are not carried by the risk port
    finally:
        config.configure(FIXTURES / "config.yaml")


def test_the_run_log_is_rotated(tmp_path):
    from keyclerk import config
    keep = config.current()["reconcile"]["keep_runs"]
    st = Rc.State(tmp_path / "state", Rc.timedelta(seconds=60))
    for i in range(keep + 5):
        st.log({"i": i}, keep)
    lines = (tmp_path / "state" / "runs.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == keep and json.loads(lines[-1])["i"] == keep + 4


def test_command_line_refuses_plain_http_to_another_host():
    with pytest.raises(InputRejected):
        Rc.parse(["--config", "c", "--records", "r", "--keycloak", "http://id.example", "--realm", "x",
                  "--secret-file", "s", "--state", "st"])


def test_an_unwritable_state_folder_still_reports_the_run_and_fails(tmp_path, monkeypatch):
    def deny(self, run, keep):
        raise PermissionError("read-only")
    monkeypatch.setattr(Rc.State, "log", deny)
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml", allow_unsigned=False), AT, Broker())
    assert "unsigned" in run["refused"] and "run log not written" in run["error"]


class MarkedBroker(Broker):
    """A broker that keeps the high-water mark, as the Keycloak target does in its state group."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.mark = None

    def high_water(self):
        return self.mark

    def set_high_water(self, revision):
        self.mark = revision


def test_an_older_signed_revision_never_replays_even_when_the_state_folder_is_lost(tmp_path):
    import shutil
    b = MarkedBroker()
    d3, d2 = doc(), doc()
    d3["revision"], d2["revision"] = 3, 2
    assert Rc.run_once(args(tmp_path, write(tmp_path, d3, "r3.yaml")), AT, b)["applied"]
    assert b.mark == 3
    shutil.rmtree(tmp_path / "state")                              # the state folder is lost
    run = Rc.run_once(args(tmp_path, write(tmp_path, d2, "r2.yaml")), AT, b)
    assert not run["applied"] and "older than revision 3" in run["refused"]
    del d3["revision"]
    run = Rc.run_once(args(tmp_path, write(tmp_path, d3, "r0.yaml")), AT, b)
    assert "older than revision 3" in run["refused"]               # once serials are used, none is a downgrade
    d3["revision"] = 4
    assert Rc.run_once(args(tmp_path, write(tmp_path, d3, "r4.yaml")), AT, b)["applied"] and b.mark == 4


def test_the_history_guard_refuses_a_serial_going_back():
    old, new = doc(), doc()
    old["revision"], new["revision"] = 5, 4
    assert any("serial only grows" in e for e in records.guard(old, new))
    new["revision"] = 5
    assert records.guard(old, new) == []


def test_damaged_state_is_set_aside_and_the_run_goes_on_and_alerts(tmp_path):
    b = Broker()
    assert Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)["applied"]
    for name in ("last-applied.json", "desired.json", "logout-queue.json"):
        (tmp_path / "state" / name).write_text("{half", encoding="utf-8")
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert run["applied"] and len(run["recovered"]) == 3 and "damaged" in run["alert"]
    assert len(list((tmp_path / "state").glob("*.corrupt-*"))) == 3


class LookupBroker(Broker):
    def user(self, anchor):
        return {"id": f"uid-of-{anchor}"}


def test_a_run_that_died_between_a_removal_and_its_logout_logs_the_person_out_next_time(tmp_path):
    b = LookupBroker()
    Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    st = Rc.State(tmp_path / "state", timedelta(minutes=5))
    st.save_intent([("/groups/office-staff", "idp:66cc-finn")])        # written ahead, then the process died
    run = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert "uid-of-idp:66cc-finn" in b.logged_out and any("interrupted" in r for r in run["recovered"])
    assert not (tmp_path / "state" / "removing.json").exists()
