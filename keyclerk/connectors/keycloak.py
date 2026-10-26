# SPDX-License-Identifier: EUPL-1.2
"""SCIM target, and Keycloak as a SCIM target, plus the one admin call SCIM lacks.

The reconciler writes grant and lease memberships through SCIM 2.0 (RFC 7644): Groups are found or created by
displayName, members added and removed with PATCH, people found by their anchor (externalId by default, or an extension
attribute that Keycloak maps from its user profile). Any SCIM-capable application is a target the same way. SCIM has
no operation on credentials, so this connector cannot write one even if asked, and the reconciler's account needs
SCIM rights only.

Keycloak 26.8 serves SCIM per realm at /realms/<realm>/scim/v2, as measured on 26.8.1: the SCIM_API feature is on, but
each realm must switch it on (scimApiEnabled); a token is accepted only with the SCIM base URL as its audience (an
audience mapper on the reconciler's client) and only from a confidential client; externalId is kept only when a
user-profile attribute is annotated kc.scim.schema.attribute: externalId (the realm's admin-only "anchor" attribute,
so a username stays a human name); and neither
groups nor users report memberships, so KeycloakTarget reads memberships through the admin API (view-users and
query-groups) while it writes them through SCIM. The one thing SCIM cannot do is end live sessions, so KeycloakTarget
also logs the person out when a membership is removed (a removed membership does not end live tokens).

Managed groups only: a group path /grants/<x> or /leases/<x> is the SCIM displayName grants:<x> or
leases:<x>; nothing else is ever read or written.

Active Directory groups are not written here: Keycloak's LDAP federation (read-only) and its group mapper in LDAP_ONLY
mode carry grant groups into a dedicated OU.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from keyclerk import guard
from keyclerk.connectors.contract import Capabilities, MembershipTarget

MAX_PAGES = 1000


def display_name(path: str) -> str:
    return path.strip("/").replace("/", ":", 1)


def group_path(name: str) -> str:
    return "/" + name.replace(":", "/", 1)


def _valid_anchor(value) -> str | None:
    """An anchor read from the broker, or None when it is missing or not a valid anchor (then the member is treated
    as anchorless and removed)."""
    try:
        return guard.anchor(value) if value else None
    except guard.InputRejected:
        return None


@dataclass
class ScimTarget(MembershipTarget):
    base: str = "http://localhost/scim/v2"
    token: str = ""                                  # short-lived, from OpenBao in production
    anchor_attribute: str = "externalId"
    name: str = "scim-target"
    caps: Capabilities = field(default_factory=lambda: Capabilities("target", ("membership",), rate_per_minute=1200))
    page: int = 200

    def __post_init__(self):
        super().__post_init__()
        self.usernames: dict[str, str] = {}   # anchor -> broker username, as read (decision 0014b)
        self.emails: dict[str, str] = {}      # anchor -> the broker's verified e-mail, as read (for edge leases)
        self.findings: list[dict] = []

    def validate(self, config: dict) -> list[str]:
        try:
            guard.broker_url(str(config.get("base", self.base)))
        except guard.InputRejected as e:
            return [f"SCIM base: {e}"]
        return []

    def _call(self, method: str, path: str, body=None, params=None):
        self.spend()
        url = f"{guard.broker_url(self.base)}{path}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}", "Accept": "application/scim+json",
                                              "Content-Type": "application/scim+json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return guard.read_response(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def _list(self, path: str, params: dict) -> list[dict]:
        out, start = [], 1
        for _ in range(MAX_PAGES):
            r = self._call("GET", path, params={**params, "startIndex": start, "count": self.page}) or {}
            res = r.get("Resources", []) if isinstance(r, dict) else []
            if not isinstance(res, list) or not all(isinstance(x, dict) for x in res):
                raise guard.InputRejected("SCIM list response has an unexpected shape")
            out += res
            start += len(res)
            if not res or start > int(r.get("totalResults", 0)):
                return out
        raise guard.InputRejected(f"more than {MAX_PAGES} pages")

    def _q(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def group(self, path: str, create: bool = False) -> dict | None:
        if not self.is_managed(path):
            raise PermissionError(f"{path} is outside the managed prefixes")
        name = display_name(path)
        found = [g for g in self._list("/Groups", {"filter": f'displayName eq "{self._q(name)}"'})
                 if g.get("displayName") == name]          # SCIM compares case-insensitively; KeyClerk does not
        if len(found) > 1:
            raise PermissionError(f"{len(found)} groups named {name}: refused until resolved")
        if found or not create:
            return found[0] if found else None
        return self._call("POST", "/Groups", {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": name})

    def user(self, anchor: str) -> dict | None:
        """The one person carrying this anchor; the anchor is validated before it reaches a filter, and the answer is
        checked to carry it (a broker that ignores the filter must not hand back someone else)."""
        guard.anchor(anchor, "anchor")
        found = self._list("/Users", {"filter": f'{self.anchor_attribute} eq "{self._q(anchor)}"'})
        if len(found) > 1:
            raise RuntimeError(f"anchor {anchor} on {len(found)} users: a collision is a security incident")
        if found and found[0].get(self.anchor_attribute) != anchor:
            raise RuntimeError("the broker returned a person without this anchor: refused")
        if found:
            guard.uuid(found[0].get("id"), "user id")
        return found[0] if found else None

    def user_by_id(self, uid: str) -> dict | None:
        """The person with this broker user id (decision 0028 phase 2: once an account is linked to its subject, it is
        addressed by it, never looked up by its anchor attribute again)."""
        uid = guard.uuid(uid, "user id")
        u = self._call("GET", f"/Users/{uid}")
        return u if isinstance(u, dict) and u.get("id") == uid else None

    def read_full(self) -> set:
        out = set()
        for g in self._list("/Groups", {}):
            path = group_path(g.get("displayName", ""))
            if not self.is_managed(path):
                continue                                   # not ours: never read further, never touched
            for m in g.get("members", []):
                uid = guard.uuid(m.get("value"), "member id")
                u = self._call("GET", f"/Users/{uid}")
                anchor = _valid_anchor(u.get(self.anchor_attribute) if isinstance(u, dict) else None)
                if anchor:
                    out.add((path, anchor))
                else:   # a member without a valid anchor is never left in a managed group
                    self.findings.append({"group": path, "member": uid, "why": "member without an anchor: removed"})
                    out.add((path, f"uid:{uid}"))
        return out

    def _members(self, gid: str, op: str, uid: str) -> None:
        self._call("PATCH", f"/Groups/{gid}", {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                               "Operations": [{"op": op, "path": "members", "value": [{"value": uid}]} if op == "add"
                                                              else {"op": "remove", "path": f'members[value eq "{uid}"]'}]})

    def on_removed(self, user: dict) -> None:
        """Hook for what SCIM cannot do (KeycloakTarget logs the person out)."""

    def _apply(self, plan: dict) -> dict:
        done = {"added": [], "removed": [], "missing_people": [], "failed": [], "logout_pending": []}
        for path, anchor in plan["remove"]:               # reductions first; a failure is reported, never silent
            try:
                g = self.group(path)
                seen = (getattr(self, "_anchors", None) or {}).get((path, anchor))   # the member the read found
                u = ({"id": guard.uuid(anchor[4:])} if anchor.startswith("uid:") else
                     {"id": seen} if seen else self.user(anchor))   # a copied attribute elsewhere never blocks a removal
                if not u or not g:
                    done["failed"].append({"group": path, "anchor": anchor, "why": "person or group not found"})
                    continue
                self._members(g["id"], "remove", u["id"])
                done["removed"].append((path, anchor))
            except Exception as e:   # noqa: BLE001 - recorded and retried next run
                done["failed"].append({"group": path, "anchor": anchor, "why": guard.safe_for_log(e, 120)})
                continue
            try:
                self.on_removed(u)
            except Exception:   # noqa: BLE001 - the logout is queued and retried until it succeeds
                done["logout_pending"].append(u["id"])
        for path, anchor in plan["add"]:
            try:
                u = self.user_by_id(anchor[4:]) if anchor.startswith("uid:") else self.user(anchor)
                if u is None:
                    done["missing_people"].append(anchor)     # the source has not delivered the person yet: next plan
                    continue
                g = self.group(path, create=True)
                self._members(g["id"], "add", u["id"])
                done["added"].append((path, anchor))
            except Exception as e:   # noqa: BLE001 - reported; never loses the removals and logouts above
                done["failed"].append({"group": path, "anchor": anchor, "why": guard.safe_for_log(e, 120)})
        return done

    def expire(self, key, at) -> None:
        self._apply({"add": [], "remove": [key]})


@dataclass
class KeycloakTarget(ScimTarget):
    """Keycloak through its SCIM API, plus one admin call SCIM lacks: log a person out on removal."""
    keycloak: str = "http://localhost:8080"
    realm: str = ""                                 # required: the tenant realm
    admin_token: str = ""                            # the writer's credential: group marker, logout
    reader_token: str = ""                           # a read-only credential: memberships, markers, role mappings
    anchor_profile_attribute: str = "anchor"         # the user-profile attribute behind SCIM externalId
    marker: str = "keyclerk.managed"                 # set on every group KeyClerk creates
    state_group: str = "keyclerk-state"             # holds the high-water mark: the newest revision applied
    logout_on_removal: bool = True                   # needs a credential that may manage users (decision 0003)
    max_attributions: int = 20                       # admin-event lookups per run
    name: str = "keycloak-target"

    def __post_init__(self):
        if not self.realm:
            raise ValueError("KeycloakTarget needs a realm")
        if self.base == "http://localhost/scim/v2":
            self.base = f"{self.keycloak}/realms/{self.realm}/scim/v2"
        super().__post_init__()

    def _admin(self, path: str, params: dict | None = None, method: str = "GET", body=None, write: bool = False):
        self.spend()
        guard.ident(self.realm, "realm")
        url = (f"{guard.broker_url(self.keycloak)}/admin/realms/{urllib.parse.quote(guard.name(self.realm, 'realm'), safe='')}{path}"
               + (f"?{urllib.parse.urlencode(params)}" if params else ""))
        tok = (self.admin_token or self.token) if write else (self.reader_token or self.admin_token or self.token)
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return guard.read_response(r, json_only=False)

    def group(self, path: str, create: bool = False) -> dict | None:
        """A managed group; one KeyClerk creates gets its marker at once, so it is recognised as ours later."""
        g = super().group(path, create=False)
        if g:
            gid = guard.uuid(g.get("id"), "group id")
            rep_ = self._admin(f"/groups/{gid}") or {}
            if (rep_.get("attributes") or {}).get(self.marker) != ["true"] or rep_.get("name") != display_name(path) \
                    or rep_.get("path") != "/" + display_name(path):
                raise PermissionError(f"{path}: the broker group is not one KeyClerk created: never written")
            return g
        if not create:
            return None
        g = super().group(path, create=True)
        gid = guard.uuid(g.get("id"), "group id")
        rep_ = self._admin(f"/groups/{gid}") or {}
        rep_["attributes"] = {**(rep_.get("attributes") or {}), self.marker: ["true"]}
        self._admin(f"/groups/{gid}", method="PUT", body=rep_, write=True)
        return g

    def read_full(self) -> set:
        """Memberships of the managed groups, through the admin API (Keycloak's SCIM does not report them)."""
        out, first = set(), 0
        self._ids, self._anchors = {}, {}                   # (group, user id) -> group id; (group, anchor) -> user id
        self.attributions_left = self.max_attributions
        for _ in range(MAX_PAGES):
            page = self._admin("/groups", {"first": first, "max": self.page, "briefRepresentation": "false"}) or []
            for g in page:
                path = group_path(str(g.get("name", "")))
                if not self.is_managed(path):
                    continue                                   # not ours: never read further, never touched
                gid = guard.uuid(g.get("id"), "group id")
                if (g.get("attributes") or {}).get(self.marker) != ["true"]:
                    self.findings.append({"group": path, "why": "named like a managed group but not created by KeyClerk: never touched"})
                    continue
                roles = self._admin(f"/groups/{gid}/role-mappings") or {}
                if roles.get("realmMappings") or roles.get("clientMappings"):
                    self.findings.append({"group": path, "why": "a managed group carries role mappings: KeyClerk groups carry none"})
                holders: dict[str, list[str]] = {}
                for mpage in range(MAX_PAGES + 1):
                    if mpage == MAX_PAGES:
                        raise guard.InputRejected(f"more than {MAX_PAGES} member pages")
                    members = self._admin(f"/groups/{gid}/members", {"first": mpage * self.page, "max": self.page,
                                                                     "briefRepresentation": "false"}) or []
                    for u in members:
                        uid = guard.uuid(u.get("id"), "user id")
                        self._ids[(path, uid)] = gid
                        anchor = _valid_anchor(u.get("username") if self.anchor_attribute == "userName" else
                                               ((u.get("attributes") or {}).get(self.anchor_profile_attribute) or [None])[0])
                        if anchor:
                            holders.setdefault(anchor, []).append(uid)
                            if u.get("username"):            # the name Warpgate and the facade know (decision 0014b)
                                self.usernames[anchor] = guard.text(str(u["username"]), "username", 255)
                            if u.get("email") and u.get("emailVerified") is True:   # SSO matches it, so only a verified one
                                self.emails[anchor] = guard.text(str(u["email"]), "email", 320)
                        else:   # a member without a valid anchor is never left in a managed group
                            self.findings.append({"group": path, "member": uid, "why": "member without an anchor: removed"})
                            out.add((path, f"uid:{uid}"))
                    if len(members) < self.page:
                        break
                for anchor, uids in holders.items():
                    self._anchors.update({(path, anchor): uids[0]} if len(uids) == 1 else {})
                    if len(uids) == 1:
                        out.add((path, anchor))
                    else:   # one anchor on several people: none of them keeps the membership
                        self.findings.append({"group": path, "anchor": anchor,
                                              "why": f"anchor on {len(uids)} people: all removed, a security incident"})
                        out |= {(path, f"uid:{u}") for u in uids}
            if len(page) < self.page:
                return out
            first += self.page
        raise guard.InputRejected(f"more than {MAX_PAGES} pages of groups")

    def _state(self) -> dict | None:
        hits = [g for g in (self._admin("/groups", {"search": self.state_group, "exact": "true",
                                                    "briefRepresentation": "false"}) or [])
                if g.get("name") == self.state_group]
        if not hits:
            return None
        rep_ = self._admin(f"/groups/{guard.uuid(hits[0].get('id'), 'group id')}") or {}
        if len(hits) > 1 or (rep_.get("attributes") or {}).get(self.marker) != ["true"] or rep_.get("path") != "/" + self.state_group:
            raise PermissionError(f"{self.state_group}: the broker group is not one KeyClerk created")
        return rep_

    def high_water(self) -> int | None:
        """The newest records revision applied to this realm, kept in the broker so a lost state folder forgets
        nothing; None before the first."""
        rep_ = self._state()
        vals = ((rep_ or {}).get("attributes") or {}).get("keyclerk.revision") or []
        try:
            return int(vals[0]) if vals else None
        except (TypeError, ValueError):
            raise guard.InputRejected("the broker's high-water mark does not read") from None

    def set_high_water(self, revision: int) -> None:
        rep_ = self._state()
        if rep_ is None:
            self._admin("/groups", method="POST", write=True,
                        body={"name": self.state_group, "attributes": {self.marker: ["true"], "keyclerk.revision": [str(revision)]}})
            return
        rep_["attributes"] = {**(rep_.get("attributes") or {}), "keyclerk.revision": [str(revision)]}
        self._admin(f"/groups/{guard.uuid(rep_.get('id'), 'group id')}", method="PUT", body=rep_, write=True)

    _anchors: dict = field(default_factory=dict)
    _ids: dict = field(default_factory=dict)

    def who_added(self, path: str, anchor: str) -> dict | None:
        """Who put this membership in the broker by hand, from the realm's admin events (best effort: events may be
        off, expired or not readable by the reader); never part of a decision, only of a finding."""
        left = getattr(self, "attributions_left", self.max_attributions)
        if left <= 0:
            return None
        self.attributions_left = left - 1
        uid = anchor[4:] if anchor.startswith("uid:") else self._anchors.get((path, anchor))
        gid = self._ids.get((path, uid)) if uid else None
        if not (uid and gid):
            return None
        try:
            evs = self._admin("/admin-events", {"resourceTypes": "GROUP_MEMBERSHIP", "operationTypes": "CREATE",
                                                "resourcePath": f"users/{guard.uuid(uid)}/groups/{guard.uuid(gid)}",
                                                "max": 5}) or []
            evs = sorted((e for e in evs if isinstance(e, dict)), key=lambda e: e.get("time") or 0, reverse=True)
        except Exception:   # noqa: BLE001 - attribution is a courtesy, never a failure
            return None
        if not evs:
            return None
        auth = evs[0].get("authDetails") or {}
        by = {"by_user": guard.safe_for_log(auth.get("userId"), 64), "by_client": guard.safe_for_log(auth.get("clientId"), 64),
              "from": guard.safe_for_log(auth.get("ipAddress"), 64), "at_ms": evs[0].get("time")}
        try:
            u = self._admin(f"/users/{guard.uuid(auth.get('userId'))}") or {}
            by["by_name"] = guard.safe_for_log(u.get("username"), 64)
        except Exception:   # noqa: BLE001 - not a person of this realm: a server administrator, say so
            by["by_name"] = "an administrator outside this realm"
        return by

    def on_removed(self, user: dict) -> None:
        if not self.logout_on_removal:
            return
        if not self.admin_token:
            return
        self.logout(user["id"])

    def logout(self, uid: str) -> None:
        """End every session of a person; raises when it fails, so the caller queues it."""
        self.spend()
        uid = guard.uuid(uid, "user id")
        req = urllib.request.Request(f"{guard.broker_url(self.keycloak)}/admin/realms/{urllib.parse.quote(guard.name(self.realm, 'realm'), safe='')}/users/{guard.uuid(uid)}/logout",
                                     method="POST", headers={"Authorization": f"Bearer {self.admin_token}"})
        with urllib.request.urlopen(req, timeout=30):
            pass
