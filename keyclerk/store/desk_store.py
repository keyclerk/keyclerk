# SPDX-License-Identifier: EUPL-1.2
"""What the desk needs of its store (decision 0022, S5): one protocol, two stores behind it.

    store: {kind: yaml}      the signed YAML store (desk.YamlStore), the default: a YAML deployment is unchanged
    store: {kind: sqlite}    the signed change log: the desk proposes through the checking signer and follows the
                             log (store/log_desk.py, from engine 0.26.0; docs/migrate-to-change-log.md moves a desk)

The desk's logic stays the same on both: it reads records with load(), commits a whole new document with commit(),
writes its activity lines with note(), and keeps its pending changes, its view log and its edge files in the store's
directory (path). Anything else a store offers is its own business and the desk never calls it; a test holds the desk
to this protocol, so the log store needs to provide exactly this.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

KINDS = ("yaml", "sqlite")


@runtime_checkable
class DeskStore(Protocol):
    path: Path                                   # the desk's directory: pending changes, view log, edge files
    scoped_judging: bool                         # whether judge() judges a change on its reach (the change log)

    def load(self) -> dict: ...                  # the records, visits joined in, a copy the caller may change
    def revision(self) -> int: ...               # the revision load() returns
    def state_key(self) -> str: ...              # changes whenever load() would return something else
    def commit(self, doc: dict, entry: dict, ops: list | None = None, tokens: list | None = None) -> dict: ...
    #                                              a whole new document, signed (or refused) as one change; ops: the
    #                                              change as judge() judged it, for a store that commits by ops
    def judge(self, ops: list[dict]) -> set[str] | None: ...   # the errors ops add on their reach; None: judge in full
    def note(self, entry: dict) -> dict: ...     # an activity line: refused, pending, withdrawn, an edge event
    def log(self, limit: int = ...) -> list[dict]: ...
    def verify_log(self) -> list[str]: ...
    def log_view(self, entry: dict) -> None: ...
    def pending(self) -> dict: ...
    def save_pending(self, p: dict) -> None: ...
    def visit_ids(self) -> list[str]: ...
    def inward(self, value: str) -> str | None: ...   # a named person as the records name them (decision 0028)
    def erase_visits(self, vids: list[str], entry: dict) -> dict | None: ...
    def close(self) -> None: ...


class StoreChoiceRefused(RuntimeError):
    """The configured store cannot be opened as given: the reason says what to change."""


def kind(cfg: dict | None) -> str:
    """The configured store kind; yaml when the configuration has no store section."""
    k = ((cfg or {}).get("store") or {}).get("kind", "yaml")
    if k not in KINDS:
        raise ValueError(f"store.kind is {k!r}: it is one of {', '.join(KINDS)}")
    return k


def open_desk_store(cfg: dict | None, path: Path, signing_key: Path | None, seed: Path | None = None,
                    signer=None) -> DeskStore:
    """The desk's store as the configuration chooses it (from engine 0.26.0 the change log is offered)."""
    if kind(cfg) == "sqlite":
        if signer is None:
            raise StoreChoiceRefused(
                "store.kind is sqlite: the desk on the signed change log proposes every change through the checking "
                "signer and never holds the records key. Start it with --signer (and --signer-token over TCP), not "
                "--signing-key.")
        from keyclerk.store.log_desk import LogStore
        return LogStore(path, signer, seed)
    from keyclerk.desk import YamlStore
    return YamlStore(path, signing_key, seed, signer=signer)
