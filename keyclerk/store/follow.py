"""A desk's store following the checking signer (decision 0022 S3).

The signer appends; the desk proposes (one writer: several writers would race for the next link). The desk appends every
link the signer answers with to its own store and checks that it reaches the same head and root the signer named. A
store that refuses the link or reaches another head is an alarm and a resync from the signer, never a signature: the
desk cannot produce one.

    f = Follower(store, client, fresh)    fresh() gives an empty store of the desk's kind, for a resync
    f.propose(change, tokens)             the signer's answer, applied; refusals come back as SignerRefused
    f.catch_up()                          the links the signer has and this store has not
    f.resync()                            a new store from the signer's links and tokens, verified, swapped in

A resync keeps what only the desk holds (visits, their events and badges) from the old store while it still reads;
the proof tokens come from the signer (op tokens). Wiring into the Desk, and the log-breaks metric, is decision 0022 S5.

In HA mode (the store holds the log's `ha` record, decision 0031 point 6) the follower adopts a size only with the
commit witness's countersignature on it, both signatures checked here: never a link a signer node only says was
committed. Without that countersignature it adopts nothing and says why (NotCommitted); the desk reads on.
"""
from __future__ import annotations

from pathlib import Path

from keyclerk.store import replay as RP
from keyclerk.store.link import StoreRefused

DESK_SIDE = ("visits", "visit_events", "badges")
PAGE = 500


class NotCommitted(RuntimeError):
    """In HA mode the signer showed no countersignature of the commit witness to follow up to: nothing adopted."""


def _ha(store) -> dict | None:
    return (store.get("head", "ha") or {}).get("value") if store.size() else None


class Follower:
    def __init__(self, store, client, fresh, from_snapshot: bool = True):
        self.store, self.client, self.fresh = store, client, fresh
        self.from_snapshot = from_snapshot          # a resync starts from the signer's newest snapshot when it has one
        self.alarms: list[str] = []

    def base(self) -> dict:
        h = self.store.head()
        return {"size": self.store.size(), "head": h.hex() if h else None}

    def propose(self, change: dict, tokens: list | None = None) -> dict:
        answer = self.client.propose(self.base(), change, tokens or [])
        self.apply(answer, tokens or [])
        return answer

    def apply(self, answer: dict, tokens: list | None = None) -> None:
        cfg = _ha(self.store)
        if cfg is not None:                       # an answer counts only with the commit witness's countersignature
            from keyclerk import ha as HA
            try:
                size, root = HA.committed(answer.get("commit") or "", cfg, self.store.pinned)
            except ValueError:
                size, root = None, None
            if size != self.store.size() + 1:
                self.catch_up()                   # adopted, if at all, as far as a countersignature shows
                return
        side = [("proof_tokens", sha, {"token": t}) for sha, t in tokens or []]
        try:
            self.store.append(answer["link"], side=side)
            self.store.add_checkpoint(answer["checkpoint"])
        except StoreRefused as e:
            self._alarm(f"the desk's store refused the signer's link: {e}")
            return
        if self.store.head().hex() != answer["hash"] or self.store.root().hex() != answer["root"] \
                or (cfg is not None and self.store.root() != root):
            self._alarm("the desk's store reached another head or root than the signer's")

    def catch_up(self) -> None:
        try:
            self._pull(self.store)
        except StoreRefused as e:
            self._alarm(f"catching up with the signer failed: {e}")

    def _pull(self, store) -> None:
        cfg = _ha(store)
        stop = root = None
        if cfg is not None:
            stop, root = self._committed(store, cfg)
        while stop is None or store.size() < stop:
            got = self.client.links(store.size(), PAGE if stop is None else min(PAGE, stop - store.size()))
            for sealed in got["links"]:
                if stop is not None and store.size() >= stop:
                    break
                store.append(sealed)
                if cfg is None and _ha(store) is not None:    # this link switched HA on: the rest only as committed
                    cfg = _ha(store)
                    stop, root = self._committed(store, cfg)
                    if stop < store.size():
                        raise StoreRefused("the commit witness has not taken the link that switched HA on")
            if not got["links"] or store.size() >= (got["size"] if stop is None else stop):
                break
        if stop is not None and root is not None and store.size() == stop and store.root() != root:
            raise StoreRefused("the links the signer served reach another root than the commit witness countersigned")
        if cfg is not None and _ha(store) != cfg:   # an HA change link was adopted: follow on under what it set
            return self._pull(store)
        if store.size() == 0:
            return                                # a log started empty and not yet seeded has no checkpoint
        cp = self.client.checkpoint(None)["checkpoint"]
        if store.checkpoint() != cp:
            store.add_checkpoint(cp)

    def _committed(self, store, cfg: dict) -> tuple[int, bytes | None]:
        """(the size to follow up to, its countersigned root). Without a countersignature that holds, the one link a
        desk adopts is an HA change link at exactly the next position (decision 0031 points 3 and 10): it is signed
        with the commit witness stopped or replaced (off, break-glass, another commit witness), carries two people's
        confirmations by the link format, and the configuration it sets governs what follows (root None: no
        countersigned root to compare)."""
        from keyclerk import ha as HA
        note = self.client.head().get("commit")
        why = None
        if note:
            try:
                return HA.committed(note, cfg, store.pinned)
            except ValueError as e:
                why = f"the signer's commit countersignature does not hold: {e}"
        nxt = self.client.links(store.size(), 1)["links"]
        if nxt:
            from keyclerk.store import link as L
            try:
                body, _ = L.open_link(nxt[0], store.pinned)
            except StoreRefused:
                body = None
            if body is not None and "ha" in body["change"] and body["seq"] == store.size():
                return store.size() + 1, None
        if why:
            raise StoreRefused(why)
        raise NotCommitted("the signer shows no countersignature of the commit witness yet (it has not committed "
                           "since it became active): nothing adopted; the desk reads on and follows again")

    def _links(self, start: int, stop: int):
        """The signer's links from start to stop, a page at a time."""
        while start < stop:
            got = self.client.links(start, min(PAGE, stop - start))["links"]
            if not got:
                raise StoreRefused(f"the signer holds fewer than {stop} links")
            yield from got
            start += len(got)

    def _alarm(self, why: str) -> None:
        self.alarms.append(why)
        self.resync()

    def fetch_snapshot(self, into: Path):
        """The signer's newest snapshot, its state file fetched a piece at a time into the directory into: (statement,
        state file), or None when the signer holds none or does not offer them. Nothing in it is trusted yet: adopt
        checks the statement's signature, every link before it and the state's hash."""
        import base64
        offer = getattr(self.client, "snapshot", None)
        got = offer() if offer else {"snapshot": None}
        if not got.get("snapshot"):
            return None
        size, path, offset = got["size"], Path(into) / f"{got['size']}.state.jsonl", 0
        with open(path, "wb") as f:
            while True:
                part = self.client.snapshot_state(size, offset, 1 << 20)
                raw = base64.b64decode(part["chunk"], validate=True)
                f.write(raw)
                offset += len(raw)
                if part["eof"] or offset > (got.get("bytes") or 0) or not raw:
                    break
        return got["snapshot"], path

    def resync(self, snapshot=None):
        """A new store built from the signer's links and tokens, verified against the signer's head, swapped in, and
        only when it extends the history this store had verified: a signer restored from an older backup that signed
        a second history is refused, never followed (it would drop what the newer branch holds, revocations too).
        With snapshot = (statement, state file) the new store adopts it (issue 28): the signer's links up to it are
        checked and kept, not applied; a snapshot that is not the signer's log is refused, as any break is."""
        try:
            kept = self.store.size()
            mine = self.store.link(kept - 1) if kept else None
        except Exception:   # noqa: BLE001 - a lost or broken store has no verified history left to keep
            kept, mine = 0, None
        new = self.fresh()
        for kind in DESK_SIDE:                    # what only the desk holds, while the old store still reads
            try:
                for key, rec in self.store.side_scan(kind):
                    new.side_put(kind, key, rec)
            except Exception:   # noqa: BLE001 - a lost or broken store gives up what it can no longer read
                pass
        after = None
        while True:
            page = self.client.tokens(after, PAGE)["tokens"]
            for sha, token in page:
                new.side_put("proof_tokens", sha, {"token": token})
            if len(page) < PAGE:
                break
            after = page[-1][0]
        scratch = None
        if snapshot is None and self.from_snapshot:
            import tempfile
            scratch = Path(tempfile.mkdtemp(prefix="kc-snapshot-"))
            try:
                snapshot = self.fetch_snapshot(scratch)
            except Exception:   # noqa: BLE001 - no snapshot to be had: the links from the genesis serve as before
                snapshot = None
        try:
            if snapshot is not None:
                sealed, state = snapshot
                from keyclerk.store import snapshot as S
                n = S.open_snapshot(sealed, new.pinned, new.realm)["size"]
                new.adopt(sealed, self._links(0, n), state)
        finally:
            if scratch is not None:
                import shutil
                shutil.rmtree(scratch, ignore_errors=True)
        self._pull(new)
        RP.verify(new, new.pinned, new.realm)
        head = self.client.head()
        if new.size() != head["size"] or new.head().hex() != head["head"] or new.root().hex() != head["root"]:
            raise StoreRefused("a resync did not reach the signer's head: the signer changed during it, resync again")
        if mine is not None and (new.size() < kept or new.link(kept - 1) != mine):
            raise StoreRefused(f"the signer's log does not extend the {kept} links this store verified: a signer "
                               "restored from an older backup, or a fork; not followed. Restore the signer's newest "
                               "state; the desk keeps its own until then")
        old, self.store = self.store, new
        try:
            old.close()
        except Exception:   # noqa: BLE001 - a lost store may not close cleanly
            pass
        return new
