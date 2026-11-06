# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 3: HA is signed realm configuration, a head record in the change log, checked by the engine."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import ha
from keyclerk.store import link as L
from keyclerk.store import note as N

WITNESS = N.vkey("witness.example/commit", N.COSIGNATURE, N.raw_public(Ed25519PrivateKey.generate()))
GOOD = {"origin": "keyclerk.example/realm", "commit_witness": WITNESS, "nodes": ["core-1", "core-2"]}


def test_a_realm_without_ha_is_unchanged():
    assert ha.of({}) is None and ha.check({}) == []


def test_a_good_configuration_checks_clean_and_is_a_head_record():
    assert ha.of({"ha": GOOD}) == GOOD and ha.check({"ha": GOOD}) == []
    assert "ha" in L.HEAD_FIELDS


@pytest.mark.parametrize("bad, why", [
    ({**GOOD, "origin": "kc-log"}, "kc-"),
    ({**GOOD, "commit_witness": N.vkey("o.example/log", N.LOG, N.raw_public(Ed25519PrivateKey.generate()))}, "cosigner key"),
    ({**GOOD, "commit_witness": "not a vkey"}, "commit_witness"),
    ({**GOOD, "nodes": ["core-1"]}, "two to four"),
    ({**GOOD, "nodes": ["core-1", "core-1"]}, "two to four"),
    ({**GOOD, "nodes": ["Core 1", "core-2"]}, "two to four"),
    ({"origin": GOOD["origin"]}, "each given"),
])
def test_a_bad_configuration_is_refused(bad, why):
    assert any(why in e for e in ha.check({"ha": bad})), ha.check({"ha": bad})
