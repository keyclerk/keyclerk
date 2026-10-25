# SPDX-License-Identifier: EUPL-1.2
"""Source connectors: the git people register and SCIM. A source normalises people into
{anchor: {"anchor", "active", "attributes": {unit, function, ...}, "version"}}; attributes it cannot vouch for are
left out, and the anchor is always an immutable id from the source, never a name or mail."""
from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from keyclerk.connectors.contract import Capabilities, Connector


def _version(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


@dataclass
class GitPeopleRegister(Connector):
    """The operator's own people: a signed people register in git. Read only."""
    path: Path = Path("people.yaml")
    name: str = "git-people-register"
    caps: Capabilities = field(default_factory=lambda: Capabilities("source", ("person",)))

    def schema(self) -> dict:
        return {"person": ["anchor", "active", "unit", "function"]}

    def validate(self, config: dict) -> list[str]:
        return [] if Path(config.get("path", self.path)).is_file() else ["the people register file does not exist"]

    def read_full(self) -> dict:
        self.spend()
        doc = yaml.safe_load(Path(self.path).read_text(encoding="utf-8")) or {}
        out = {}
        for p in doc.get("people", []):
            attrs = {k: p[k] for k in ("unit", "function") if k in p}
            item = {"anchor": p["anchor"], "active": bool(p.get("active", True)), "attributes": attrs}
            out[p["anchor"]] = {**item, "version": _version(item)}
        return out


@dataclass
class ScimSource(Connector):
    """Reads people from any SCIM 2.0 service provider (RFC 7643, 7644): Keycloak 26.8's SCIM API or a tenant IdP.
    The anchor is the SCIM id (or externalId when configured); unit and function come from the Enterprise User
    extension (department) and title. Delta uses meta.lastModified."""
    base: str = "http://localhost/scim/v2"
    token: str = ""
    anchor_from: str = "id"            # id or externalId
    page: int = 100
    name: str = "scim-source"
    caps: Capabilities = field(default_factory=lambda: Capabilities("source", ("person",), delta=True, events=True))
    webhook_key: bytes = b""

    ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

    def validate(self, config: dict) -> list[str]:
        errs = []
        if not str(config.get("base", self.base)).startswith(("https://", "http://localhost", "http://127.0.0.1")):
            errs.append("SCIM base must be https (plain http only to localhost)")
        if config.get("anchor_from", self.anchor_from) not in ("id", "externalId"):
            errs.append("anchor_from must be id or externalId")
        return errs

    def _get(self, path: str, params: dict) -> dict:
        self.spend()
        url = f"{self.base}{path}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"Accept": "application/scim+json", "Authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def _norm(self, u: dict) -> dict:
        ent = u.get(self.ENT, {})
        attrs = {k: v for k, v in (("unit", ent.get("department")), ("function", u.get("title"))) if v}
        item = {"anchor": u[self.anchor_from], "active": bool(u.get("active", True)), "attributes": attrs}
        return {**item, "version": u.get("meta", {}).get("version") or _version(item),
                "modified": u.get("meta", {}).get("lastModified")}

    def _pages(self, params: dict) -> list[dict]:
        out, start = [], 1
        while True:
            r = self._get("/Users", {**params, "startIndex": start, "count": self.page})
            res = r.get("Resources", [])
            out += res
            start += len(res)
            if not res or start > int(r.get("totalResults", 0)):
                return out

    def read_full(self) -> dict:
        return {i["anchor"]: i for i in (self._norm(u) for u in self._pages({}))}

    def read_delta(self, cursor: str | None):
        """Changes since cursor (an RFC 3339 time); returns (items, next cursor). A full read stays the authority."""
        params = {"filter": f'meta.lastModified gt "{cursor}"'} if cursor else {}
        items = [self._norm(u) for u in self._pages(params)]
        nxt = max([cursor or ""] + [i["modified"] or "" for i in items])
        return {i["anchor"]: i for i in items}, nxt

    def verify_event(self, raw: bytes, headers: dict):
        """A change notification signed with HMAC-SHA256 (the Standard Webhooks shape); unsigned or wrong is None."""
        sig = headers.get("webhook-signature", "")
        if not self.webhook_key or not sig:
            return None
        mac = hmac.new(self.webhook_key, f"{headers.get('webhook-id', '')}.{headers.get('webhook-timestamp', '')}.".encode() + raw,
                       hashlib.sha256).hexdigest()
        return json.loads(raw) if hmac.compare_digest(sig, mac) else None
