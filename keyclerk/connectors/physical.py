# SPDX-License-Identifier: EUPL-1.2
"""Physical targets under the connector contract: the PACS head-end and the OSDP controller behind
the same describe, read_full, plan, apply and expire as every other target. Both store the lease end themselves
(expiry_native), so a door keeps enforcing it when the IT link is cut."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from keyclerk.connectors.contract import Capabilities, Connector
from keyclerk.piam import pacs
from keyclerk.piam.core import Allowlist


@dataclass
class PacsTarget(Connector):
    conn: object = None                                  # a piam.pacs.PacsConnector (SimulatedPacs in CI)
    at: datetime | None = None                           # the plan's moment; the reconciler sets it each cycle
    name: str = "pacs-target"
    caps: Capabilities = field(default_factory=lambda: Capabilities("target", ("cardholder", "credential"), events=True,
                                                                    expiry_native=True, rate_per_minute=300))
    data_classes: tuple = ("operational", "badge_picture", "presence")

    def read_full(self) -> dict:
        self.spend()
        return self.conn.cardholders()

    def plan(self, desired: dict, observed: dict) -> dict:
        p = pacs.plan(desired, observed, self.at)
        return {**p, "want": desired}

    def _apply(self, plan: dict) -> dict:
        pacs.apply(self.conn, plan["want"], plan, self.at)
        return {k: plan[k] for k in ("create", "update", "expire", "findings")}

    def observe(self) -> list[dict]:
        return self.conn.events()

    def expire(self, key, at: datetime) -> None:
        self.conn.expire(key, at)


@dataclass
class OsdpTarget(Connector):
    controller: object = None                            # a piam.osdp_controller.Controller
    name: str = "osdp-target"
    caps: Capabilities = field(default_factory=lambda: Capabilities("target", ("credential",), events=True,
                                                                    expiry_native=True, rate_per_minute=600))
    data_classes: tuple = ("operational", "presence")

    def read_full(self) -> dict:
        al = self.controller.allowlist
        return {"records": frozenset(al.by_badge.values()), "revoked": frozenset(al.revoked)}

    def plan(self, desired: dict, observed: dict) -> dict:
        want, have = set(desired["records"]), set(observed["records"])
        return {"add": sorted(r.badge for r in want - have), "remove": sorted(r.badge for r in have - want),
                "revoke": sorted(set(desired["revoked"]) - set(observed["revoked"])), "desired": desired}

    def _apply(self, plan: dict) -> dict:
        d = plan["desired"]
        changed = self.controller.reload(Allowlist(list(d["records"]), set(d["revoked"])))
        return {"reloaded": True, "changed": changed}
