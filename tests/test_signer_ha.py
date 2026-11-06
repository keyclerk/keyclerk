# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 points 4, 6, 7 and 11 on the signer: in HA mode a node signs only while active, answers a change only
once the commit witness took it, and names itself in the link; a standby follows the committed links and takes over
when the committed head stands still for its hold time; an active node that lost the race is deposed, drops what it
never committed and resyncs; a lost answer is committed again when the change is asked again."""
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import commit_witness as C
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import note as N
from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - the fixture

ORIGIN = "keyclerk.example/ha-test"


def verify(token, nonce, by):
    t = json.loads(token)
    if t["nonce"] != nonce or t["by"] != by:
        raise ValueError("this proof is for another statement")


def confirm(s, mode, value, node=None, people=None):
    """The security officer's and a root trust owner's proofs of the HA change statement on s's head."""
    from keyclerk import ha as HA
    from keyclerk.store import replay
    root = replay.records(s.replica)["root"]
    people = people or (root["officer"], root["holders"][0]["anchor"])
    size, head = s.replica.size(), s.replica.head().hex()
    return [(by, json.dumps({"nonce": HA.statement("example", by, mode, size, head, value, node), "by": by}))
            for by in people]
WKEY = Ed25519PrivateKey.from_private_bytes(b"w" * 32)


class Net:
    """The commit witness in process, with a switch to cut a node off or lose an answer after the witness acted."""

    def __init__(self, w):
        self.t, self.down, self.lose_answer, self.drop_commit = C.in_process(w), False, False, False

    def __call__(self, method, url, body, timeout):
        if self.down or (self.drop_commit and method == "POST"):
            raise OSError("no route to the commit witness")
        out = self.t(method, url, body, timeout)
        if self.lose_answer and method == "POST":
            self.lose_answer = False
            raise OSError("the answer was lost")
        return out


@pytest.fixture
def pair(world, tmp_path):  # noqa: F811
    s, key = world["signer"], world["key"]
    vkey = N.vkey("witness.example/commit", N.COSIGNATURE, N.raw_public(WKEY))
    cfg = {"origin": ORIGIN, "commit_witness": vkey, "nodes": ["node-a", "node-b"]}
    s.ha_change("set", cfg, None, confirm(s, "set", cfg), verify)  # two people switch HA on (operator 2026-11-05)
    pub = s.public_key()
    s.close()                                              # the witness seeded from the stopped signer (the runbook)
    with pytest.raises(ValueError, match="does not name origin"):
        C.export_seed(tmp_path / "signer-state", key, "keyclerk.example/another", tmp_path / "seed")
    got = C.export_seed(tmp_path / "signer-state", key, ORIGIN, tmp_path / "seed")
    assert got["public_key"] == pub
    C.reseed(tmp_path / "cw", ORIGIN, pub, tmp_path / "seed" / "links.jsonl", "operator", "HA switched on",
             lambda: 1_800_000_000, (tmp_path / "seed" / "checkpoint.note").read_text(encoding="utf-8"),
             WKEY, "witness.example/commit")
    w = C.CommitWitness(WKEY, "witness.example/commit", tmp_path / "cw", [N.vkey(ORIGIN, N.LOG, N.raw_public(key))])
    shutil.copytree(tmp_path / "signer-state", tmp_path / "signer-b")
    a, b = Signer(key, tmp_path / "signer-state"), Signer(key, tmp_path / "signer-b")
    world["signer"] = a                                   # closed by the fixture
    clock = [1000.0]
    nets = {"a": Net(w), "b": Net(w)}
    a.configure_ha("node-a", C.CommitClient("http://cw", transport=nets["a"]), 30, lambda: clock[0])
    b.configure_ha("node-b", C.CommitClient("http://cw", transport=nets["b"]), 30, lambda: clock[0])
    yield {"a": a, "b": b, "w": w, "clock": clock, "nets": nets, "tmp": tmp_path}
    b.close()


def _wait(p, node):
    """Two ticks the hold time apart: the head stood still, so the node takes over."""
    node.ha_tick()
    p["clock"][0] += 31
    return node.ha_tick()


def _entry(s):
    from keyclerk.store import link as L
    return L.open_link(s.replica.link(s.replica.size() - 1), s.public_key())[0]["change"]["entry"]


def _base(s):
    return {"size": s.replica.size(), "head": s.replica.head().hex()}


def _add(p, s):
    return s.propose(_base(s), {"ops": change_ops(p["tmp"], ADD, {"signer": s}),
                                "entry": {"change_id": "C-" + "ab12" * 3, "action": "add_member", "actor": "keyclerk:test"}}, [])


def test_a_standby_signs_nothing_and_takes_over_when_the_committed_head_stands_still(pair):
    a, w = pair["a"], pair["w"]
    with pytest.raises(SignerRefused, match="standby"):
        _add(pair, a)
    assert a.ha_tick() == "standby"                       # the head seen; the hold time starts
    pair["clock"][0] += 10
    assert a.ha_tick() == "standby"                       # not yet
    pair["clock"][0] += 21
    assert a.ha_tick() == "active"
    assert w.commits[ORIGIN].size == a.replica.size()     # everything it holds is committed, the takeover link last
    last = _entry(a)
    assert (last["action"], last["node"]) == ("ha_takeover", "node-a")
    assert a.head()["ha"] == {"node": "node-a", "role": "active", "why": f"took over at {a.replica.size() - 1}"}


def test_the_active_answers_only_committed_changes_and_names_itself(pair):
    a, w = pair["a"], pair["w"]
    assert _wait(pair, a) == "active"
    out = _add(pair, a)
    assert w.commits[ORIGIN].size == a.replica.size() and out["hash"] == w.commits[ORIGIN].head.hex()
    assert _entry(a)["node"] == "node-a"


def test_a_standby_follows_and_an_active_that_lost_the_race_is_deposed(pair):
    a, b, w = pair["a"], pair["b"], pair["w"]
    assert _wait(pair, a) == "active"
    _add(pair, a)
    assert b.ha_tick() == "standby" and b.replica.size() == w.commits[ORIGIN].size     # it follows
    assert b.replica.head() == a.replica.head()
    pair["nets"]["a"].down = True                         # a is cut off (a pause, a partition)
    assert _wait(pair, b) == "active"                     # the committed head stood still: b takes over
    pair["nets"]["a"].down = False
    with pytest.raises(SignerRefused, match="deposed"):
        _add(pair, a)                                     # a comes back and signs: the witness holds more
    assert a.ha["role"] == "standby"
    assert a.replica.size() == w.commits[ORIGIN].size and a.replica.head() == b.replica.head()   # resynced
    assert _add(pair, b)["hash"] == w.commits[ORIGIN].head.hex()


def test_a_signed_link_the_witness_never_took_is_dropped_on_deposition(pair):
    a, b, w = pair["a"], pair["b"], pair["w"]
    assert _wait(pair, a) == "active"
    pair["nets"]["a"].down = True
    with pytest.raises(SignerRefused, match="does not answer"):
        _add(pair, a)                                     # refused before signing: the witness is away
    assert a.replica.size() == w.commits[ORIGIN].size
    pair["nets"]["a"].down = False
    assert _wait(pair, b) == "active"
    pair["nets"]["a"].lose_answer = False
    with pytest.raises(SignerRefused, match="deposed"):
        _add(pair, a)
    assert a.replica.head() == w.commits[ORIGIN].head


def test_a_lost_answer_is_committed_and_answered_when_asked_again(pair):
    a, w = pair["a"], pair["w"]
    assert _wait(pair, a) == "active"
    base = _base(a)
    change = {"ops": change_ops(pair["tmp"], ADD, {"signer": a}),
              "entry": {"change_id": "C-" + "cd34" * 3, "action": "add_member", "actor": "keyclerk:test"}}
    pair["nets"]["a"].lose_answer = True
    with pytest.raises(SignerRefused, match="outcome is unknown"):
        a.propose(base, change, [])
    assert w.commits[ORIGIN].size == a.replica.size()     # the witness took it; only the answer was lost
    again = a.propose(base, change, [])
    assert again["duplicate"] == a.replica.size() - 1
    with pytest.raises(SignerRefused, match="does not answer"):
        pair["nets"]["a"].down = True
        a.propose(base, change, [])                       # never answered while the witness cannot confirm it


def test_an_entry_names_only_a_node_in_its_shape(world):  # noqa: F811
    from keyclerk.signer import _entry_shape
    _entry_shape({"change_id": "C-a1b2c3", "action": "add_member", "node": "node-a"})
    with pytest.raises(SignerRefused, match="entry node"):
        _entry_shape({"action": "add_member", "node": "Node A, the one in the basement"})


def test_an_empty_commit_witness_is_an_outage_never_a_log_of_size_0(pair):
    a, tmp = pair["a"], pair["tmp"]
    empty = C.CommitWitness(WKEY, "witness.example/commit", tmp / "cw-empty",
                            [N.vkey(ORIGIN, N.LOG, N.raw_public(a.key))])
    a.ha["client"] = C.CommitClient("http://cw", transport=C.in_process(empty))
    size = a.replica.size()
    assert _wait(pair, a) == "standby"                    # no takeover, and nothing forgotten
    assert a.replica.size() == size and empty.commits[ORIGIN].size == 0


def test_the_ha_loop_runs_in_its_own_thread_and_promotes_a_standby(pair, capsys):
    import time
    a = pair["a"]
    a.ha["hold"] = 0.0
    a.start_ha(0.01)
    deadline = time.monotonic() + 10
    err = ""
    while "HA node node-a is active" not in err and time.monotonic() < deadline:
        time.sleep(0.02)
        err += capsys.readouterr().err
    assert a.ha["role"] == "active" and "HA node node-a is standby" in err and "HA node node-a is active" in err


@pytest.mark.parametrize("args, why", [(["--ha-node", "node-a"], "both --ha-node and --commit-witness"),
                                       (["--commit-witness", "http://cw"], "both --ha-node and --commit-witness"),
                                       (["--ha-node", "node-a", "--commit-witness", "http://cw", "--ha-hold", "1"],
                                        "at least 5 seconds")])
def test_the_signer_refuses_half_an_ha_configuration(args, why):
    from keyclerk.signer import main
    with pytest.raises(SystemExit, match=why):
        main(["--key", "k", "--state", "s", "--config", "c", *args])


def test_only_the_active_serves_and_only_what_was_committed(pair):
    from keyclerk.signer import STANDBY
    a, b, w = pair["a"], pair["b"], pair["w"]
    for call in (b.head, lambda: b.links(0, 10), lambda: b.checkpoint(None)):
        with pytest.raises(SignerRefused, match=STANDBY):
            call()
    assert _wait(pair, a) == "active"
    committed = a.head()
    pair["nets"]["a"].drop_commit = True                  # signed, then the commit was never taken
    with pytest.raises(SignerRefused, match="outcome is unknown"):
        _add(pair, a)
    assert a.replica.size() == committed["size"] + 1 == w.commits[ORIGIN].size + 1
    head = a.head()
    assert (head["size"], head["head"], head["root"]) == (committed["size"], committed["head"], committed["root"])
    assert a.links(0, 500)["size"] == committed["size"] and len(a.links(0, 500)["links"]) == committed["size"]
    assert a.checkpoint(None)["checkpoint"] == committed["checkpoint"]


def test_an_active_that_sees_another_commit_is_deposed_by_its_own_tick(pair):
    a, b, w = pair["a"], pair["b"], pair["w"]
    assert _wait(pair, a) == "active"
    pair["nets"]["a"].down = True
    assert _wait(pair, b) == "active"
    pair["nets"]["a"].down = False
    assert a.ha_tick() == "standby" and a.ha["why"].startswith("deposed")
    assert a.replica.head() == w.commits[ORIGIN].head


def test_an_active_cut_off_from_the_commit_witness_steps_down_after_its_hold_time(pair):
    a = pair["a"]
    assert _wait(pair, a) == "active"
    pair["nets"]["a"].down = True
    pair["clock"][0] += 10
    assert a.ha_tick() == "active"                        # a short loss: it stays
    pair["clock"][0] += 25
    assert a.ha_tick() == "standby" and a.ha["why"] == "lost the commit witness"
    pair["nets"]["a"].down = False
    assert _wait(pair, a) == "active"                     # nobody else moved: it takes over again


def test_a_desk_follows_the_active_node_through_a_failover(pair, tmp_path):
    import threading
    from keyclerk.signer import SignerClient, serve
    from keyclerk.store.log_desk import LogStore
    a, b, w = pair["a"], pair["b"], pair["w"]
    (tmp_path / "token").write_text("a-desk-token", encoding="utf-8")
    servers = {}
    for name, node in (("a", a), ("b", b)):
        srv = serve(node, "tcp:127.0.0.1:0", "a-desk-token")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers[name] = srv
    addr = {n: f"tcp:127.0.0.1:{s.server_address[1]}" for n, s in servers.items()}
    try:
        assert _wait(pair, a) == "active"
        client = SignerClient(f"{addr['b']},{addr['a']}", str(tmp_path / "token"))   # b first: a standby, skipped
        desk = LogStore(tmp_path / "desk", client)
        assert client.address == addr["a"] and desk.follower.store.size() == w.commits[ORIGIN].size
        _add(pair, a)
        desk.refresh()
        assert desk.follower.store.head() == w.commits[ORIGIN].head
        pair["nets"]["a"].down = True                     # a loses the witness; b takes over, a steps down
        pair["clock"][0] += 31
        a.ha_tick()
        assert _wait(pair, b) == "active" and a.ha["role"] == "standby"
        out = client.propose(_base(b), {"ops": change_ops(pair["tmp"], ADD, {"signer": b}),
                                        "entry": {"change_id": "C-" + "ef56" * 3, "action": "add_member",
                                                  "actor": "keyclerk:test"}}, [])
        assert client.address == addr["b"] and out["hash"] == w.commits[ORIGIN].head.hex()
        desk.refresh()
        assert desk.follower.store.head() == w.commits[ORIGIN].head    # it followed b, across the takeover link
        desk.close()
    finally:
        for s in servers.values():
            s.shutdown()
            s.server_close()


def test_detection_witnesses_see_only_committed_heads_from_the_active_node(pair):
    """Decision 0031 point 8: a detection witness is sent only checkpoints the commit witness took, by the active node,
    so it can never hold a head a takeover drops (and halt the new active)."""
    from keyclerk import witness as W
    a, b = pair["a"], pair["b"]
    det = W.Witness(Ed25519PrivateKey.from_private_bytes(b"d" * 32), "witness.example/detect", pair["tmp"] / "det",
                    [N.vkey(ORIGIN, N.LOG, N.raw_public(a.key))])

    def local(method, url, body, timeout):
        return det.add_checkpoint(body) if method == "POST" else det.checkpoint(url.rsplit("/", 2)[-2])
    for s in (a, b):
        s.configure_witness({"origin": ORIGIN}, [W.Cosigner("http://det.invalid", det.vkey, transport=local)])
    assert b.witness_check() is None                      # a standby sends nothing
    assert _wait(pair, a) == "active"
    _add(pair, a)
    pair["nets"]["a"].drop_commit = True                  # a signs a link the commit witness never takes
    with pytest.raises(SignerRefused, match="unknown"):
        _add(pair, a)
    assert a.replica.size() == a.ha["committed"] + 1
    out = a.witness_check()
    assert out and all(o["size"] == a.ha["committed"] for o in out.values())   # the committed head, not the tail


def test_a_deposed_node_stops_sending_to_detection_witnesses(pair):
    from keyclerk import witness as W
    a, b = pair["a"], pair["b"]
    det = W.Witness(Ed25519PrivateKey.from_private_bytes(b"d" * 32), "witness.example/detect", pair["tmp"] / "det",
                    [N.vkey(ORIGIN, N.LOG, N.raw_public(a.key))])

    def local(method, url, body, timeout):
        return det.add_checkpoint(body) if method == "POST" else det.checkpoint(url.rsplit("/", 2)[-2])
    a.configure_witness({"origin": ORIGIN}, [W.Cosigner("http://det.invalid", det.vkey, transport=local)])
    assert _wait(pair, a) == "active"
    _add(pair, a)
    assert a.witness_check()                              # active: it sends its committed head
    pair["nets"]["a"].down = True
    assert _wait(pair, b) == "active"                     # b takes over
    pair["nets"]["a"].down = False
    with pytest.raises(SignerRefused, match="deposed"):
        _add(pair, a)
    assert a.ha["role"] == "standby" and a.ha.get("committed", 0) > 0
    assert a.witness_check() is None                      # deposed: it remembers a committed size, and sends nothing


def test_a_desk_adopts_a_break_glass_link_and_notes_it_as_an_incident(pair, world):  # noqa: F811
    """Decision 0031 point 10 on the desk: the break-glass link is signed with the commit witness stopped, so no
    countersignature covers it; the desk adopts it at the next position as an HA change link, follows on under HA off,
    and notes one finding for the officer and the SIEM."""
    from keyclerk.store.log_desk import LogStore
    a = pair["a"]
    assert _wait(pair, a) == "active"
    _add(pair, a)
    desk = LogStore(pair["tmp"] / "desk", a)
    try:
        assert desk.store.size() == a.replica.size()
        a.close()                                         # the commit witness is lost; node a breaks the glass
        s = world["signer"] = Signer(world["key"], a.state)
        down = Net(pair["w"])
        down.down = True
        s.ha_change("break_glass", None, "node-a", confirm(s, "break_glass", None, "node-a"), verify,
                    C.CommitClient("http://cw", transport=down))
        desk._signer = s
        desk.follower.client = s
        desk.refresh()
        assert desk.store.size() == s.replica.size() and desk.store.get("head", "ha") is None
        found = [x for x in desk.log(20) if x.get("action") == "ha_break_glass"]
        assert len(found) == 1 and found[0]["outcome"] == "finding"
        desk.refresh()                                    # noted once
        assert len([x for x in desk.log(20) if x.get("action") == "ha_break_glass"]) == 1
    finally:
        desk.close()


def test_an_idle_active_beats_and_is_never_deposed(pair):
    """Decision 0031 point 7, amended after the hub soak: with nothing changing, the committed head stood still and the
    standby took over at every hold time, then the other way, for ever. The active's beat (its checkpoint committed
    again, countersigned at the witness's time) moves the head a standby watches, and adds no link."""
    a, b, w, clock = pair["a"], pair["b"], pair["w"], pair["clock"]
    w.clock = lambda: int(clock[0])                       # the witness's own time, as the standby never compares it
    assert _wait(pair, a) == "active"
    size = w.commits[ORIGIN].size
    for _ in range(30):                                   # ten minutes of ticks at a sixth of the hold, nothing changing
        clock[0] += 5
        assert a.ha_tick() == "active"
        assert b.ha_tick() == "standby"
    assert w.commits[ORIGIN].size == size                 # beats are no links


def test_a_standby_takes_over_when_the_beats_stop(pair):
    a, b, w, clock = pair["a"], pair["b"], pair["w"], pair["clock"]
    w.clock = lambda: int(clock[0])
    assert _wait(pair, a) == "active"
    for _ in range(4):
        clock[0] += 5
        a.ha_tick()
        b.ha_tick()
    for _ in range(8):                                    # a paused: no beat for longer than the hold time
        clock[0] += 5
        role = b.ha_tick()
    assert role == "active" and a.ha_tick() == "standby"  # a wakes, sees another commit and is deposed: a liveness
    # guard (it passed before the beat too); the beat's own falsifiers follow


def test_a_beat_moves_the_head_even_when_the_witness_clock_stands_still(pair):
    """The witness countersigns a beat at its last time + 1 at least: with max(clock, last time) a witness whose clock
    stands still or was set back left the head still, and the standby took over again."""
    a, b, w, clock = pair["a"], pair["b"], pair["w"], pair["clock"]
    w.clock = lambda: 1000                                 # far behind the seeded checkpoint's time, and frozen
    assert _wait(pair, a) == "active"
    for _ in range(30):
        clock[0] += 5
        assert a.ha_tick() == "active"
        assert b.ha_tick() == "standby"


def test_a_beat_at_a_size_the_witness_no_longer_holds_is_refused(pair):
    from keyclerk.store import note as N
    a, b, w, clock = pair["a"], pair["b"], pair["w"], pair["clock"]
    w.clock = lambda: int(clock[0])
    assert _wait(pair, a) == "active"
    stale = (a.ha["committed"], a.ha["note"])             # what a would beat with: its committed checkpoint
    clock[0] += 40
    assert _wait(pair, b) == "active"                     # a paused: b took over
    status, _, _ = a.ha["client"].commit(stale[0], [], stale[1])
    assert status == 409 and a.ha["committed"] == stale[0]
    assert a.ha_tick() == "standby"
    assert N.split(stale[1])                              # the note a beat sends is the committed one, whole


def test_an_active_whose_own_answer_was_lost_adopts_its_commit(pair):
    """The witness took the active's change but the answer was lost: the active used to call itself deposed, so for
    a whole hold time nobody beat and a takeover added a link. It now sees its own links committed and stays."""
    a, b, w, clock = pair["a"], pair["b"], pair["w"], pair["clock"]
    w.clock = lambda: int(clock[0])
    assert _wait(pair, a) == "active"
    pair["nets"]["a"].lose_answer = True
    with pytest.raises(SignerRefused):
        _add(pair, a)                                     # committed at the witness, answer lost
    size = w.commits[ORIGIN].size
    assert a.ha_tick() == "active" and a.ha["committed"] == size
    for _ in range(12):
        clock[0] += 5
        assert a.ha_tick() == "active" and b.ha_tick() == "standby"
    assert w.commits[ORIGIN].size == size                 # no takeover link
