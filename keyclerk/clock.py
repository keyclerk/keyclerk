"""One clock for a judgement (decision 0022 S4): every engine check reads "now" from here, never datetime.now(), so a
whole check, and the old and new states a signer compares, are judged at one moment, and a scoped check can be
compared exactly with the full one (a test holds that no check module reads the clock any other way).

    with clock.at(t): ...        judge at t
    with clock.fixed(): ...      judge at one moment: the one already set, else now
    clock.now()                  the moment set, else the current time (UTC)
"""
from __future__ import annotations

import contextlib
import contextvars
from datetime import datetime, timezone

_NOW: contextvars.ContextVar[datetime | None] = contextvars.ContextVar("keyclerk_now", default=None)


def now() -> datetime:
    t = _NOW.get()
    return t if t is not None else datetime.now(timezone.utc)


@contextlib.contextmanager
def at(t: datetime):
    if t.tzinfo is None:
        raise ValueError("a judgement's moment has a zone")
    token = _NOW.set(t)
    try:
        yield t
    finally:
        _NOW.reset(token)


@contextlib.contextmanager
def fixed():
    with at(now()) as t:
        yield t
