# SPDX-License-Identifier: EUPL-1.2
"""0.29 review S7: the identity map had no bound on its time. A map from the future (a reconciler clock set ahead, or
a map signed for later) refused every map after it; a map of last year still named the bastion account for a person
whose account has since changed. Now a map more than five minutes ahead is refused and is no floor, and a map older
than edges.identity_map_max_hours (default 24) vouches for nobody until the next map arrives."""
from datetime import datetime, timedelta, timezone

import pytest
from test_edge_sealer import core, idmap, seal  # noqa: F401

from keyclerk import edge as E
from keyclerk.signer import SignerRefused


def test_a_map_from_the_future_is_refused(core):
    with pytest.raises(SignerRefused, match="ahead of the signer's clock"):
        core["signer"].identity_map({"sealed": idmap(core, at=datetime.now(timezone.utc) + timedelta(hours=1))})


def test_a_kept_map_from_the_future_does_not_lock_out_the_next(core):
    """A map an earlier version kept with a time ahead is no floor: the reconciler's next, correct map is taken."""
    s = core["signer"]
    sealer = s.edges()
    sealer._write("identity.json", {"at": E._iso(datetime.now(timezone.utc) + timedelta(days=30)), "revision": 1})
    assert s.identity_map({"sealed": idmap(core)})["people"] == 1


def test_an_old_map_vouches_for_nobody(core):
    with pytest.raises(SignerRefused, match="older than 24 hours"):
        core["signer"].identity_map({"sealed": idmap(core, at=datetime.now(timezone.utc) - timedelta(hours=25))})


def test_a_kept_map_ages_out_and_the_next_one_brings_the_bundle_back(core):
    s = core["signer"]
    assert s.identity_map({"sealed": idmap(core)})["people"] == 1
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    s.configure_edge_clock(lambda: later)
    with pytest.raises(SignerRefused, match="older than 24 hours"):
        seal(core, identity_map=None)
    assert seal(core, identity_map=idmap(core, at=later))["bundle"]


def test_the_age_is_the_deployments_to_set(core, monkeypatch):
    from keyclerk import config
    real = config.current
    monkeypatch.setattr(config, "current", lambda: {**real(), "edges": {"identity_map_max_hours": 72}})
    assert core["signer"].identity_map({"sealed": idmap(core, at=datetime.now(timezone.utc) - timedelta(hours=48))})
