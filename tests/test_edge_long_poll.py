# SPDX-License-Identifier: EUPL-1.2
"""Decision 0026 over HTTP: the bundle long-poll. An edge names the serial it holds and a wait; the desk answers when
the edge's bundle says something new, or when the wait ends, always with a fresh bundle. Without a wait, a pull is as
before. A replayed long-poll is refused like any replayed request."""
import threading
import time

import pytest

from keyclerk import config
from keyclerk import edge as E

from test_edge_api import OFFICER_KEY, call, ceiling, edge_server  # noqa: F401 - the fixture


def _ready(base):
    code, _ = call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, ceiling())},
                   cookie="eva", csrf="c-eva", signed=False)
    assert code == 200
    code, b = call(base, "GET", "/edge/bundle")
    assert code == 200
    return b


def _serial(b) -> int:
    return E.opened(b)["serial"]


def _timed(base, path):
    t = time.monotonic()
    code, b = call(base, "GET", path)
    return code, b, time.monotonic() - t


def test_without_a_wait_a_pull_answers_at_once(edge_server):
    base, _ = edge_server
    held = _ready(base)
    code, b, took = _timed(base, f"/edge/bundle?after={_serial(held)}")
    assert code == 200 and took < 2 and _serial(b) > _serial(held)


def test_nothing_new_waits_and_answers_with_a_fresh_bundle_when_the_wait_ends(edge_server):
    base, _ = edge_server
    held = _ready(base)
    code, b, took = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=2")
    assert code == 200 and 1.8 <= took < 6
    assert _serial(b) > _serial(held) and E.bundle_digest(b) == E.bundle_digest(held)   # same content, renewed


def test_a_change_for_the_edge_answers_the_wait_at_once(edge_server):
    base, _ = edge_server
    held = _ready(base)

    def narrow():
        time.sleep(0.5)
        call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, {**ceiling(2), "classes": ["low"]})},
             cookie="eva", csrf="c-eva", signed=False)
    threading.Thread(target=narrow).start()
    code, b, took = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=10")
    assert code == 200 and took < 5
    assert E.bundle_digest(b) != E.bundle_digest(held) and E.opened(E.opened(b)["ceiling"])["serial"] == 2


def test_a_wake_that_changes_nothing_for_the_edge_keeps_waiting(edge_server):
    base, desk = edge_server
    held = _ready(base)

    def unrelated():
        time.sleep(0.4)
        desk._bundles_may_change()                   # a commit elsewhere: the edge's bundle says the same
    threading.Thread(target=unrelated).start()
    code, b, took = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=2")
    assert code == 200 and took >= 1.8 and E.bundle_digest(b) == E.bundle_digest(held)


def test_an_unknown_serial_answers_at_once(edge_server):
    base, _ = edge_server
    _ready(base)
    code, b, took = _timed(base, "/edge/bundle?after=999999&wait=10")
    assert code == 200 and took < 2


def test_a_second_wait_from_a_one_node_edge_answers_the_first(edge_server):
    base, _ = edge_server
    held = _ready(base)
    first = {}

    def wait_long():
        first["r"] = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=20")
    t = threading.Thread(target=wait_long)
    t.start()
    time.sleep(0.8)
    second = threading.Thread(target=lambda: _timed(base, f"/edge/bundle?after={_serial(held)}&wait=2"))
    second.start()
    t.join(10)
    assert not t.is_alive() and first["r"][0] == 200 and first["r"][2] < 5     # answered when the second opened
    second.join(10)


def test_over_the_cap_a_wait_is_a_plain_pull(edge_server, monkeypatch):
    base, _ = edge_server
    held = _ready(base)
    monkeypatch.setitem(config.current(), "edge", {"long_poll_max": 0})
    code, _, took = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=10")
    assert code == 200 and took < 2


def test_a_wait_above_the_maximum_is_held_to_it(edge_server, monkeypatch):
    base, desk = edge_server
    held = _ready(base)
    monkeypatch.setattr(type(desk), "LONG_POLL_MAX_WAIT", 1)
    code, _, took = _timed(base, f"/edge/bundle?after={_serial(held)}&wait=999")
    assert code == 200 and 0.8 <= took < 4


@pytest.mark.parametrize("query", ["serial=1&wait=5", "wait=abc", "wait=0", "wait=-3"])
def test_malformed_waits_are_refused(edge_server, query):
    base, _ = edge_server
    _ready(base)
    code, body = call(base, "GET", f"/edge/bundle?{query}")
    assert code == 422 and ("wait" in str(body) or "serial" in str(body)), (code, body)


def test_a_replayed_long_poll_is_refused(edge_server):
    base, _ = edge_server
    held = _ready(base)
    path = f"/edge/bundle?after={_serial(held)}&wait=1"
    header = E.sign_request(__import__("test_edges").EDGE_KEY, "plant-a", "GET", "/api/v1" + path, b"")
    assert call(base, "GET", path, header=header)[0] == 200
    assert call(base, "GET", path, header=header)[0] == 401
