# SPDX-License-Identifier: EUPL-1.2
"""The reconciler links a subject only on an applying run, for a wanted membership, when one account carries the attribute."""
import uuid

from tests.test_reconcile_log import UidBroker, _rows, world  # noqa: F401 (fixture)

from tests.test_reconcile import AT

from keyclerk import reconcile as Rc


class PlantedBroker(UidBroker):
    """One extra account (mallory) carries a copy of the holder's anchor attribute and sits in a managed group."""

    def __init__(self, group, attr, mallory):
        super().__init__()
        self.planted = (group, attr)
        self.mallory = mallory
        self.have.add(self.planted)

    @property
    def _anchors(self):
        m = {(g, a): self.uid(a) for g, a in self.have if not a.startswith("uid:")}
        if self.planted in self.have:
            m[self.planted] = self.mallory
        return m


def _holder(signer):
    anchor, row = sorted(_rows(signer).items())[0]
    return anchor, row["idp"]


def _plant(w):
    anchor, attr = _holder(w["signer"])
    mallory = str(uuid.uuid4())
    w["broker"] = PlantedBroker("/grants/zz-planted", attr, mallory)
    return anchor, mallory


def test_a_dry_run_never_links_anyone(world):
    anchor, mallory = _plant(world)
    world["args"].apply = False
    Rc.run_once(world["args"], at=AT, target=world["broker"])
    linked = {a: r.get("sub") for a, r in _rows(world["signer"]).items() if r.get("sub")}
    assert linked == {}, f"a dry run wrote {len(linked)} subject links to the signer"


def test_a_copied_attribute_in_an_unwanted_group_never_becomes_the_holders_subject(world):
    anchor, mallory = _plant(world)
    Rc.run_once(world["args"], at=AT, target=world["broker"])
    assert _rows(world["signer"])[anchor].get("sub") != mallory, \
        "the holder's mapping row was linked to the account carrying a copy of the attribute"
