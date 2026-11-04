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
"""
from __future__ import annotations

from pathlib import Path

from keyclerk.store import replay as RP
from keyclerk.store.link import StoreRefused

DESK_SIDE = ("visits", "visit_events", "badges")
PAGE = 500


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
        side = [("proof_tokens", sha, {"token": t}) for sha, t in tokens or []]
        try:
            self.store.append(answer["link"], side=side)
            self.store.add_checkpoint(answer["checkpoint"])
        except StoreRefused as e:
            self._alarm(f"the desk's store refused the signer's link: {e}")
            return
        if self.store.head().hex() != answer["hash"] or self.store.root().hex() != answer["root"]:
            self._alarm("the desk's store reached another head or root than the signer's")

    def catch_up(self) -> None:
        try:
            self._pull(self.store)
        except StoreRefused as e:
            self._alarm(f"catching up with the signer failed: {e}")

    def _pull(self, store) -> None:
        while True:
            got = self.client.links(store.size(), PAGE)
            for sealed in got["links"]:
                store.append(sealed)
            if store.size() >= got["size"] or not got["links"]:
                break
        if store.size() == 0:
            return                                # a log started empty and not yet seeded has no checkpoint
        cp = self.client.checkpoint(None)["checkpoint"]
        if store.checkpoint() != cp:
            store.add_checkpoint(cp)

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
