# SPDX-License-Identifier: EUPL-1.2
"""The reconciler on the signed change log (decision 0022 S5 step T5, decision 0028): it plans in internal anchors
from its own verified replica, tells the broker its own names, links each account it sees to its subject, then
addresses it by that subject only; a mapping the log does not vouch for, or an account it cannot name, stops the run."""
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_reconcile import AT, FIXTURES, Broker, args

from keyclerk import anchors as A
from keyclerk import reconcile as Rc
from keyclerk.signer import Signer
from keyclerk.store.log_desk import LogStore


class UidBroker(Broker):
    """The fake broker with user ids: a member carries the anchor attribute; adds say how the person was found."""

    def __init__(self):
        super().__init__()
        self.uid_of: dict[str, str] = {}             # anchor attribute -> user id
        self.found: list[str] = []                   # "attribute" or "subject", per person looked up

    def uid(self, attr):
        return self.uid_of.setdefault(attr, str(uuid.uuid4()))

    @property
    def _anchors(self):
        return {(g, a): self.uid(a) for g, a in self.have if not a.startswith("uid:")}

    def user(self, attr):
        self.found.append("attribute")
        return {"id": self.uid(attr)}

    def _apply(self, plan):
        by_uid = {u: a for a, u in self.uid_of.items()}
        done = {"added": [], "removed": [], "failed": [], "logout_pending": [], "missing_people": []}
        for g, a in plan["remove"]:
            attr = by_uid.get(a[4:], a) if a.startswith("uid:") else a
            self.have = {(x, y) for x, y in self.have if not (x == g and (y == attr or y == a))}
            done["removed"].append((g, a))
        for g, a in plan["add"]:
            if a.startswith("uid:"):
                self.found.append("subject")
                a = by_uid[a[4:]]
            else:
                self.user(a)
            self.have.add((g, a))
            done["added"].append((g, a))
        return done


@pytest.fixture
def world(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    desk = LogStore(tmp_path / "desk", signer, FIXTURES / "records.yaml")
    key = tmp_path / "records.pub"
    key.write_text(signer.public_key(), encoding="utf-8")
    a = args(tmp_path, None, records=None, log_replica=str(tmp_path / "reconciler" / "log.db"), signer_client=signer,
             records_key=str(key), signer=None, signer_token=None)
    yield {"signer": signer, "desk": desk, "args": a, "broker": UidBroker()}
    desk.close()
    signer.close()


def _run(w):
    return Rc.run_once(w["args"], at=AT, target=w["broker"])


def _rows(signer):
    return dict(signer.replica.side_scan("anchor_map"))


def test_the_broker_hears_its_own_names_never_internal_anchors(world):
    run = _run(world)
    assert run["applied"] and not run.get("refused") and run["add"], run
    names = {a for _, a in world["broker"].have}
    idps = {r["idp"] for r in _rows(world["signer"]).values()}
    assert names and names <= idps and not any(A.is_internal(n) for n in names)


def test_people_seen_are_linked_to_their_subject_then_addressed_by_it(world):
    _run(world)
    linked = {a: r["sub"] for a, r in _rows(world["signer"]).items() if r.get("sub")}
    assert linked and set(linked.values()) <= set(world["broker"].uid_of.values())
    g, attr = sorted(world["broker"].have)[0]                    # someone takes them out by hand: the next run restores
    world["broker"].have.discard((g, attr))
    world["broker"].found.clear()
    run = _run(world)
    assert (g, attr) in world["broker"].have and run["add"]
    assert world["broker"].found == ["subject"]                   # never looked up by the attribute again
    world["desk"].refresh()                                       # the desk learns the links too: sign-in by subject
    a = next(a for a, r in _rows(world["signer"]).items() if r["idp"] == attr)
    assert A.resolve(world["desk"].store, {"sub": world["broker"].uid_of[attr]}) == a


def test_a_moved_attribute_names_nobody_once_linked(world):
    _run(world)
    g, attr = sorted(world["broker"].have)[0]
    mallory = str(uuid.uuid4())
    world["broker"].have.add((g, f"uid:{mallory}"))               # another account now carries the attribute
    ids = Rc._from_log(world["args"], world["broker"])[3]
    try:
        from keyclerk.store.log_reconcile import Identities
        from keyclerk.store import replay as RP
        known = Identities(RP.records(ids["store"]), ids["store"])
        assert known.inward(attr, mallory) is None and known.inward(attr, world["broker"].uid_of[attr]) is not None
    finally:
        ids["source"].close()
    run = _run(world)
    assert (g, f"uid:{mallory}") not in world["broker"].have and run["intrusions_removed"] >= 1


def test_an_account_the_mapping_does_not_name_stops_the_run(world):
    _run(world)
    g, attr = sorted(world["broker"].have)[0]                    # someone the records want in a group
    wanted = next(a for a, r in _rows(world["signer"]).items() if r["idp"] == attr)
    world["signer"].replica.side_delete("anchor_map", wanted)     # erased from the mapping, still in the records
    world["broker"].have.discard((g, attr))
    run = _run(world)
    assert "the mapping does not name" in (run.get("refused") or ""), run
    assert (g, attr) not in world["broker"].have                  # nothing written for someone it cannot name


def test_a_mapping_row_the_log_does_not_vouch_for_stops_the_run(world):
    anchor, row = next(iter(_rows(world["signer"]).items()))
    world["signer"].replica.side_put("anchor_map", anchor, {**row, "idp": "idp:99ee-mallory"})   # re-pointed
    run = _run(world)
    assert "do not match the log" in run["refused"] and not world["broker"].have


def test_a_replica_signed_by_another_key_is_refused(world, tmp_path):
    other = tmp_path / "other.pub"
    other.write_text(Signer(Ed25519PrivateKey.generate(), tmp_path / "other-signer").public_key(), encoding="utf-8")
    world["args"].records_key = str(other)
    run = _run(world)
    assert "not signed by the records key" in (run.get("refused") or "") and not world["broker"].have


def test_the_command_line_takes_the_log_or_the_file_never_both():
    with pytest.raises(SystemExit):
        Rc.parse(["--config", "c", "--keycloak", "https://id.example", "--realm", "r", "--secret-file", "s",
                  "--state", "st"])
    with pytest.raises(SystemExit):
        Rc.parse(["--config", "c", "--keycloak", "https://id.example", "--realm", "r", "--secret-file", "s",
                  "--state", "st", "--log-replica", "x.db"])
    a = Rc.parse(["--config", "c", "--keycloak", "https://id.example", "--realm", "r", "--secret-file", "s",
                  "--state", "st", "--log-replica", "x.db", "--signer", "unix:/s", "--records-key", "k"])
    assert a.log_replica == "x.db" and a.records is None
