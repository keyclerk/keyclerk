# SPDX-License-Identifier: EUPL-1.2
"""A removal removes the member the read found, whatever other accounts carry."""
from tests.test_connectors import scim  # noqa: F401 (fixture)

from keyclerk.connectors.keycloak import KeycloakTarget


def test_a_copied_anchor_on_a_bystander_account_never_keeps_a_revoked_membership(scim):
    data, url = scim
    ann = data.add_user("idp:ann")
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    kc.apply({"add": [("/grants/x", "idp:ann")], "remove": []}, "k1", dry_run=False)
    made = next(g for g in data.groups.values() if g["displayName"] == "grants:x")
    assert made["members"] == [{"value": ann}]
    data.add_user("idp:ann")                         # a second account carries a copy of the anchor; it joins nothing
    have = kc.read_full()
    assert have == {("/grants/x", "idp:ann")}         # one holder in the group: no finding, ann is read as herself
    r = kc.apply(kc.plan(set(), have), "k2", dry_run=False)   # the grant ended: the records want nothing
    assert made["members"] == [], f"ann kept the membership; the removal failed: {r['failed']}"
