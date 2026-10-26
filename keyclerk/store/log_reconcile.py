# SPDX-License-Identifier: EUPL-1.2
"""The reconciler on the signed change log (decision 0022 S5 step T5, decision 0028).

The reconciler keeps its own replica of the log, followed from the checking signer and checked against the records
key it pins itself, so where the links come from does not matter. Its plan speaks internal anchors; the broker speaks
its own ids. People cross between them here, and only here:

    out:  an internal anchor -> the broker's user id once the account is linked to its subject (phase 2), the
          identity provider's id (the broker's anchor attribute) until then
    in:   a member of a managed group -> the internal anchor of the subject it is, once linked; through the anchor
          attribute while the row is not; an attribute whose row is linked to another subject names nobody

A mapping row counts only when the log's accounts record vouches for it, and a plan that names an internal anchor no
row maps is refused: nothing is ever written to the broker for someone the reconciler cannot name there. Each account
seen through its attribute and not linked yet is linked to its subject at the signer (op link_subject), so the
reconciler stops looking people up by the attribute once it knows them.
"""
from __future__ import annotations

from pathlib import Path

from keyclerk import anchors as A
from keyclerk.store import replay as RP
from keyclerk.store.follow import Follower
from keyclerk.store.sqlite import SqliteStore

MAX_LINKS_PER_RUN = 500


class LogRefused(Exception):
    """The log, or its mapping, cannot be trusted for this run: the run applies nothing."""


class LogRecords:
    """The reconciler's replica: caught up with the signer, verified, and its mapping rows checked against the log."""

    def __init__(self, path: Path, signer, pinned: str, realm: str):
        self.signer, self.pinned, self.realm = signer, pinned, realm
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.follower = Follower(SqliteStore(self.path, pinned, realm), signer, self._fresh)

    @property
    def store(self):
        return self.follower.store

    def _fresh(self):
        for suffix in ("", "-wal", "-shm"):
            Path(str(self.path) + ".resync" + suffix).unlink(missing_ok=True)
        return SqliteStore(Path(str(self.path) + ".resync"), self.pinned, self.realm)

    def read(self) -> tuple[dict, str, int | None]:
        """(records, head hex, revision) after catching up; LogRefused when the replica or its mapping fails."""
        try:
            self.follower.catch_up()
        except Exception as e:   # noqa: BLE001 - a link the pinned key did not sign, a broken resync: nothing applied
            raise LogRefused(f"the replica could not follow the signer: {str(e)[:200]}") from None
        if self.follower.alarms:
            raise LogRefused(f"the replica could not follow the signer: {self.follower.alarms[-1]}")
        try:
            RP.verify(self.store, self.pinned, self.realm)
        except Exception as e:   # noqa: BLE001 - StoreRefused or a broken store: either way nothing is applied
            raise LogRefused(f"the replica does not verify against the pinned records key: {e}") from None
        self._sync_rows()
        head = self.store.head()
        return RP.records(self.store), head.hex() if head else "", RP.revision(self.store)

    def _sync_rows(self) -> None:
        """The signer's mapping, mirrored: new and linked rows taken, rows the signer no longer holds (erased) dropped."""
        sync_rows(self.store, self.signer)

    def close(self) -> None:
        self.store.close()


def sync_rows(store, signer) -> None:
    """A replica's mapping made the signer's: rows put where they differ, rows the signer no longer has deleted, with
    their reverse entries (an erasure reaches every copy, decision 0028)."""
    held, after = {}, None
    while True:
        page = signer.anchors(after, 500)["anchors"]
        held.update(dict(page))
        if len(page) < 500:
            break
        after = page[-1][0]
    mine = dict(store.side_scan("anchor_map"))
    items: list[tuple[str, str, dict | None]] = []
    for anchor, row in mine.items():
        if anchor not in held:
            items += [("anchor_map", anchor, None), ("anchor_idp", A.idp_key(row["idp"]), None)]
            if row.get("sub"):
                items.append(("anchor_idp", A.sub_key(row["sub"]), None))
    for anchor, row in held.items():
        if mine.get(anchor) != row:
            items += [("anchor_map", anchor, row), ("anchor_idp", A.idp_key(row["idp"]), {"anchor": anchor})]
            if row.get("sub"):
                items.append(("anchor_idp", A.sub_key(row["sub"]), {"anchor": anchor}))
    if hasattr(store, "side_put_many"):
        store.side_put_many(items)                    # one transaction: a sync of 20,000 rows is not 60,000
        return
    for kind, key, rec in items:
        store.side_delete(kind, key) if rec is None else store.side_put(kind, key, rec)


class Identities:
    """The mapping as the reconciler trusts it: rows the log's accounts records vouch for, both ways."""

    def __init__(self, doc: dict, store):
        commits = {a["anchor"]: a["commit"] for a in doc.get("accounts") or []}
        self.rows: dict[str, dict] = {}
        bad = []
        for anchor, row in store.side_scan("anchor_map"):
            if anchor not in commits:
                continue                              # an account erased from the log: its row names nobody now
            if not A.row_matches(row, [commits[anchor]]):
                bad.append(anchor)
                continue
            self.rows[anchor] = row
        if bad:
            raise LogRefused(f"{len(bad)} mapping rows do not match the log's accounts records (first {bad[0]}): the "
                             "mapping was changed outside the signer; restore it from the signer (resync)")
        self.by_idp = {row["idp"]: a for a, row in self.rows.items()}
        self.by_sub = {row["sub"]: a for a, row in self.rows.items() if row.get("sub")}

    def out(self, anchor: str) -> str | None:
        """How the broker is told about this account: uid:<subject> once linked, its anchor attribute before."""
        row = self.rows.get(anchor)
        if row is None:
            return None
        return f"uid:{row['sub']}" if row.get("sub") else row["idp"]

    def inward(self, attribute: str | None, uid: str | None) -> str | None:
        if uid and uid in self.by_sub:
            return self.by_sub[uid]                   # phase 2: the subject counts, whatever its attribute says now
        a = self.by_idp.get(attribute) if attribute else None
        if a is None:
            return None
        sub = self.rows[a].get("sub")
        return a if not sub or sub == uid else None   # linked to another subject: a moved attribute names nobody


class LogTarget:
    """A broker target that speaks internal anchors: the plan in, the broker's names out, members back in."""

    def __init__(self, inner, ids: Identities):
        self.inner, self.ids = inner, ids
        self.to_link: dict[str, tuple[str, str, str]] = {}   # anchor -> (uid, group path, attribute)
        self.usernames: dict[str, str] = {}
        self.emails: dict[str, str] = {}

    def __getattr__(self, name):                      # high_water, set_high_water, logout, who_added, ...
        return getattr(self.inner, name)

    @property
    def findings(self):
        return self.inner.findings

    def read_full(self) -> set:
        raw = self.inner.read_full()
        uids = getattr(self.inner, "_anchors", {}) or {}
        out = set()
        for path, x in raw:
            if x.startswith("uid:"):
                out.add((path, x))                    # a member without an anchor: an intruder, as before
                continue
            uid = uids.get((path, x))
            anchor = self.ids.inward(x, uid)
            if anchor is None:
                out.add((path, f"uid:{uid}" if uid else x))   # nobody the records name: removed as an intruder
                continue
            out.add((path, anchor))
            if uid and not self.ids.rows[anchor].get("sub") and uid not in self.ids.by_sub:
                self.to_link[anchor] = (uid, path, x)
        for attr, name in (getattr(self.inner, "usernames", {}) or {}).items():
            a = self.ids.inward(attr, None)
            if a:
                self.usernames[a] = name
        for attr, mail in (getattr(self.inner, "emails", {}) or {}).items():
            a = self.ids.inward(attr, None)
            if a:
                self.emails[a] = mail
        return out

    def plan(self, want: set, have: set) -> dict:
        unmapped = sorted({a for _, a in want if A.is_internal(a) and self.ids.out(a) is None})
        if unmapped:
            raise LogRefused(f"the records want {len(unmapped)} accounts the mapping does not name (first {unmapped[0]}): "
                             "nothing is written for someone the reconciler cannot name in the broker")
        return self.inner.plan(want, have)

    def user(self, anchor: str) -> dict | None:
        """The broker's person for an account of the plan (an interrupted run's removals)."""
        name = self.ids.out(anchor) if A.is_internal(anchor) else anchor
        if name is None:
            return None
        return {"id": name[4:]} if name.startswith("uid:") else self.inner.user(name)

    def _outward(self, item):
        path, a = item
        return (path, self.ids.out(a) if A.is_internal(a) else a)

    def apply(self, plan: dict, key: str, dry_run: bool = True) -> dict:
        broker = {**plan, "add": [self._outward(x) for x in plan["add"]],
                  "remove": [self._outward(x) for x in plan["remove"]]}
        return self.inner.apply(broker, key=key, dry_run=dry_run)

    def link_subjects(self, signer, want: set) -> list[dict]:
        """Phase 2: each account seen through its attribute, not linked yet, linked to its subject at the signer. Only
        a membership the records want (an unwanted one is about to be removed: its holder proves nothing), and only
        when exactly one account in the realm carries the attribute and it is this one; a link is never undone, so a
        copied attribute must not become someone's subject."""
        findings = []
        for anchor, (uid, path, attr) in sorted(self.to_link.items())[:MAX_LINKS_PER_RUN]:
            if (path, anchor) not in want:
                continue
            try:
                holder = self.inner.user(attr)            # raises when the attribute is on more than one account
                if not holder or holder.get("id") != uid:
                    findings.append({"anchor": anchor, "why": "not linked: the attribute's one holder is not this member"})
                    continue
                signer.link_subject(anchor, uid)
            except Exception as e:   # noqa: BLE001 - a refused link is a finding; the run goes on by attribute
                findings.append({"anchor": anchor, "why": f"not linked to its subject: {str(e)[:160]}"})
        return findings
