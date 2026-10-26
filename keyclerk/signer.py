# SPDX-License-Identifier: EUPL-1.2
"""The checking signer (replan D1, decision 0015): the records key lives in its own process, and it signs a revision only
after checking it.

The desk process serves people and unauthenticated endpoints; whoever holds it could sign anything with a key it holds
(an adversarial review's finding). The signer holds the records key instead, readable only by its own user, and answers on a local socket.
Before it signs a revision it checks, against its own copy of the last revision it signed:
  - the revision is exactly one higher, and the records' history is not rewritten (records.guard);
  - the records add no engine check error the last revision did not have (the desk's own rule, now enforced here);
  - with approval proofs configured, no approval key lacks a valid proof that the last revision did not already lack,
    and every high-risk record the revision adds or widens carries its proposer's own proof (replan D2).
A log line that vouches for a revision (records_sha256) is signed only as part of that commit; other log lines (a
refusal, a view) are signed as they come. So a compromised desk can still refuse, delay or log noise, but it can no
longer have a change signed that the engine's checks or the approvers did not allow.

    python -m keyclerk.signer --key records.key --state DIR --config keyclerk.yaml --listen tcp:127.0.0.1:8099 --token FILE
                              [--listen unix:/run/keyclerk/signer.sock]
                              [--approval-issuer URL --approval-audience CLIENT --approval-jwks URL]
    python -m keyclerk.signer --key records.key --state DIR --config keyclerk.yaml --adopt STORE   (once, desk stopped)
    python -m keyclerk.signer resume --key records.key --state DIR --config keyclerk.yaml --by NAME --reason TEXT
                              [--accept-baseline]      (ends a freeze of signing, at the terminal, signer stopped)

Protocol: one JSON object per line, answered by one. {"op": "ping"} | {"op": "public_key"} | {"op": "sign_line", "body": {...}} |
{"op": "commit", "raw": records text, "body": {...}}; over TCP each request carries "token"; a refusal is {"refused": why}.

The change log (decision 0022 S3). The signer keeps its own replica, state/replica.db, built only from links it signed
itself: it never takes state from the desk (a compromised desk must not feed it a false state). One signer per state
directory (an exclusive lock beside the replica). At every start it verifies the replica (every signature, the chain,
root and head against the newest checkpoint) and refuses to sign when that fails, or when the replica's newest
checkpoint is older than what this signer last signed (state/log-mark.json: a replica restored from an older backup
never signs on top of a newer history, 0019).
    {"op": "migrate"}                                   once: its own last signed YAML revision (state/last.yaml, its own
                                                        signature checked, not just its hash) becomes the genesis and migrate links
    {"op": "start", "realm"}                            once, with no signed YAML revision to migrate: an empty log, whose
                                                        first proposal is link 0, judged against an empty state
    {"op": "head"}                                      {size, head, root, fence, revision, checkpoint, migration}, and
                                                        frozen: why, while signing is frozen (reads go on, 0022 S5)
    {"op": "propose", "base": {"size", "head"}, "change": {"ops", "entry"}, "tokens": [[sha256, token], ...],
     "rows": [mapping row, ...]}
        base is a staleness guard only; the change is applied to the replica in one transaction, checked there against
        the replica's own state (records.guard, no new engine check error, approval and proposer proofs against the
        tokens), and only then kept, with its per-change checkpoint: {link, checkpoint, hash, root, revision}. A link
        signed for a change the checks then refuse never leaves the signer. The same change proposed again on the
        base it was applied to (its answer was lost) is answered with its link, {duplicate: seq, link, checkpoint,
        hash}, never applied twice. rows are the mapping rows of the people the change brings in (decision 0028),
        each accepted only when a record the change puts carries its commitment.
    {"op": "links", "start", "limit" <= 500}            {links, size}: a desk's catch-up or resync
    {"op": "tokens", "after", "limit" <= 500}           {tokens}: the proof tokens, for a desk that lost its store; every
                                                        call is a signed line in state/audit.jsonl (bearer-ish material)
    {"op": "anchors", "after", "limit" <= 500}          {anchors}: the mapping rows (decision 0028), for a desk that
                                                        migrates or lost its store; audited like tokens
    {"op": "checkpoint", "size"}                        {checkpoint}: the newest, or the one at a size
    {"op": "link_subject", "anchor", "sub"}             {linked}: the reconciler records the broker subject of an
                                                        account, once (decision 0028 phase 2); audited
Once migrated, commit is refused: changes are proposed. sign_line goes on for the lines that vouch for no change.

The replica's token table (its side table) is not in the log and erasable, like the desk's: an erasure of personal
data (decision 0022 point 3) has to reach the signer's replica too, not only the desk's store.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import socketserver
import sys
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAX_REQUEST = 32 * 1024 * 1024


class SignerRefused(Exception):
    """The signer will not sign this: the reason says why."""


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _norm(errs) -> set[str]:
    return {e.removesuffix(" (now)") for e in errs}


class Signer:
    FENCE = 1                                     # the fencing number; signer failover (0013's model) raises it later
    MAX_PER_KIND = 500                            # records of one kind one change may touch: what bounds a change now that
                                                  # the records schema's whole-document caps no longer do (0022)

    def __init__(self, key: Ed25519PrivateKey, state: Path, proofs=None, full_check: bool = False):
        self.key, self.state, self.proofs = key, Path(state), proofs
        self.full_check = full_check              # every change judged by the full check (the reference path, 0022 S4)
        self.state.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.replica = None                       # the change log, once migrated (decision 0022 S3)
        self.broken: str | None = None            # why it will not sign, when its replica failed verification
        self._held = None
        self._open_replica()
        if self.broken is None:
            self.broken = self.verify_audit()
        if self.broken is None:
            self.broken = self.frozen()
        self.config_pending = self.replica is not None and self._config_sha() != self._read("config.sha256")
        self.last_check = None                    # the last background full check's result
        self.not_ready: str | None = None         # why the replica's records do not meet this engine's schema
        self.check_schema()

    def check_schema(self) -> str | None:
        """Whether the replica's records meet this engine's records schema (at start and after each background run).
        When they do not, the signer still starts and answers (resume, health, the background check), reports not
        ready with the reason and next steps, alarms, and refuses every change: nothing is signed unjudged."""
        from keyclerk import metrics, records
        from keyclerk.store import replay
        if self.replica is None or self.broken:
            return None
        bad = records.validate(replay.records(self.replica), log_backed=True)
        self.not_ready = (f"the replica's records do not meet this engine's records schema ({bad[0][:160]}): no change "
                          "can be judged on them. Run the records migration for this engine version, or roll the engine "
                          "back") if bad else None
        if self.not_ready:
            metrics.inc("keyclerk_check_alarms_total", kind="needs_migration")
        return self.not_ready

    # --- freezing and resuming, each a signed line in the audit log (decision 0022 S4) ----------------------------

    def _audit_ops(self, ops: tuple[str, ...]) -> list[dict]:
        f = self.state / "audit.jsonl"
        if not f.exists():
            return []
        return [e for e in (json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip())
                if e.get("op") in ops]

    def frozen(self) -> str | None:
        """Why signing is frozen, or None: frozen while frozen.json is there, and while the audit log's last freeze line
        has no resume line after it (removing the file by hand resumes nothing)."""
        from keyclerk import fullcheck
        lines = self._audit_ops(("freeze", "resume"))
        last = lines[-1] if lines else None
        f = self.state / "frozen.json"
        if f.exists():
            v = json.loads(f.read_text(encoding="utf-8"))
            return fullcheck.frozen_message(v["at"], v["why"])
        if last is not None and last["op"] == "freeze":
            return fullcheck.frozen_message(last["at"], last["why"])
        return None

    def _freeze(self, why: str) -> None:
        from keyclerk import fullcheck
        self._audit({"op": "freeze", "why": why})      # signed first: the file alone is never the record
        fullcheck.freeze(self.state, why)
        self.broken = self.frozen()

    def resume(self, by: str, reason: str, accept_baseline: bool) -> dict:
        """End a freeze, accountably: a signed audit line names who resumed, why, the freeze it ends, and whether the
        current state becomes the baseline the next background check compares against (only then is it). Signing
        stays judged in full until a background full check passes again."""
        import getpass
        from keyclerk import fullcheck
        with self.lock:
            why = self.frozen()
            if why is None:
                raise SignerRefused("signing is not frozen: there is nothing to resume")
            if self.broken != why:
                raise SignerRefused(f"the signer refuses to sign for another reason: {self.broken}")
            if not (isinstance(by, str) and by.strip() and isinstance(reason, str) and len(reason.strip()) >= 10):
                raise SignerRefused("a resume names who resumes (--by) and why (--reason, at least 10 characters)")
            ends = (self._audit_ops(("freeze",)) or [{}])[-1].get("why") or why
            line = {"op": "resume", "by": by.strip(), "os_user": getpass.getuser(), "why": reason.strip(),
                    "ends": ends, "accept_baseline": bool(accept_baseline)}
            self._audit(line)
            if accept_baseline:
                fullcheck.accept_baseline(self.replica, self.state)
            (self.state / "frozen.json").unlink(missing_ok=True)
            self.broken, self.config_pending = None, True
            return line

    # --- the background full check (decision 0022 S4) -------------------------------------------------------------

    @staticmethod
    def _schema_sha() -> str:
        from keyclerk import config
        return hashlib.sha256(json.dumps(config.schema("records"), sort_keys=True).encode()).hexdigest()

    @classmethod
    def _config_sha(cls) -> str:
        """What the records do not hold but every judgement depends on: the configuration, the engine's version, its
        records schema and its policy bundle. A change in any of them (an upgrade, a new policy) is judged in full until
        a background full check passes."""
        from keyclerk import __version__, config
        policy = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                  for f in sorted((Path(__file__).parent / "policy").glob("*.wasm"))}
        facts = {"config": config.current(), "engine": __version__, "schema": cls._schema_sha(), "policy": policy}
        return hashlib.sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()

    def _read(self, name: str) -> str | None:
        f = self.state / name
        return f.read_text(encoding="utf-8").strip() if f.exists() else None

    def background_check(self):
        """One background full check of the replica, on a snapshot. Until one passes after a start with a configuration
        it has not checked, every change is judged in full (the configuration is not in the records)."""
        from keyclerk import fullcheck
        if self.replica is None or self.broken:
            return None
        sha, schema = self._config_sha(), self._schema_sha()
        result = fullcheck.run(self.replica, self.state, schema_changed=schema != self._read("schema.sha256"))
        self.last_check = result
        self.check_schema()
        if result.frozen:
            self._freeze(result.frozen)
        elif result.ok and not [a for a in result.alarms if a.startswith(("incomplete", "needs migration"))]:
            (self.state / "config.sha256").write_text(sha, encoding="utf-8")
            (self.state / "schema.sha256").write_text(schema, encoding="utf-8")
            self.config_pending = False
        return result

    def start_background(self, every_seconds: float = 24 * 3600) -> threading.Thread:
        """The background full check at start and then every every_seconds, in a thread of its own."""
        def loop():
            import time as _t
            while True:
                try:
                    self.background_check()
                except Exception as e:   # noqa: BLE001 - incomplete: an alarm, retried at the next run (a
                    # transient failure must not halt signing)
                    from keyclerk import metrics
                    metrics.inc("keyclerk_check_alarms_total", kind="incomplete")
                    sys.stderr.write(f"keyclerk.signer: background full check incomplete: {e}\n")
                _t.sleep(every_seconds)
        t = threading.Thread(target=loop, name="keyclerk-full-check", daemon=True)
        t.start()
        return t

    def verify_audit(self) -> str | None:
        """Why the signer's audit log does not verify (every line signed by this key, each naming the one before), or
        None; a line cut by a crash is set aside. A restored signer state must pass this too (decision 0019)."""
        f = self.state / "audit.jsonl"
        if not f.exists() or not f.stat().st_size:
            return None
        data = f.read_bytes()
        if not data.endswith(b"\n"):              # a crash in the middle of an append
            keep = data.rfind(b"\n") + 1
            (self.state / f"audit.jsonl.partial-{_now().replace(':', '')}").write_bytes(data[keep:])
            with f.open("r+b") as h:
                h.truncate(keep)
            data = data[:keep]
        prev, pub = "0" * 64, self.key.public_key()
        for n, line in enumerate(data.splitlines(), 1):
            try:
                e = json.loads(line)
                body = {k: v for k, v in e.items() if k not in ("sha256", "signature")}
                sha = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
                if e["prev"] != prev or e["sha256"] != sha:
                    raise ValueError("it does not follow the line before")
                pub.verify(bytes.fromhex(e["signature"]), sha.encode())
            except Exception as ex:   # noqa: BLE001 - unreadable, unlinked or unsigned: the chain is broken here
                return (f"the signer's audit log does not verify at line {n} ({type(ex).__name__}): restore the signer's "
                        "state from a backup as a whole (decision 0019)")
            prev = sha
        self._audit_prev = prev
        return None

    # --- the replica: only links this signer signed ----------------------------------------------------------------

    def _mark(self) -> dict | None:
        f = self.state / "log-mark.json"
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    def _write_mark(self) -> None:
        from keyclerk.store import replay
        r = self.replica
        tmp = self.state / "log-mark.json.tmp"
        tmp.write_text(json.dumps({"realm": r.realm, "size": r.size(), "head": r.head().hex() if r.head() else None,
                                   "revision": replay.revision(r)}), encoding="utf-8", newline="\n")
        os.replace(tmp, self.state / "log-mark.json")

    def _hold(self) -> None:
        from keyclerk.store.sqlite import hold
        try:
            self._held = hold(self.state / "replica.lock",
                              f"another signer holds {self.state}: one signer per state directory (decision 0022). "
                              "Stop the other signer, or give this one a state directory of its own")
        except Exception as e:
            raise SignerRefused(str(e)) from None

    def _open_replica(self) -> None:
        """At every start: the replica verified (signatures, chain, root and head against the newest checkpoint) and no
        older than what this signer last signed; otherwise it keeps answering, and refuses to sign, saying why."""
        from keyclerk.store import link as L
        from keyclerk.store import replay
        from keyclerk.store.sqlite import SqliteStore
        db, mark = self.state / "replica.db", self._mark()
        if mark is None and not db.exists():
            return                                # not migrated yet: the YAML commits of decision 0015
        if mark is None or not db.exists():
            self.broken = (f"the signer's state holds {'a replica but no mark of what it signed' if mark is None else 'a mark of '
                           + str(mark['size']) + ' signed links but no replica'}: restore the signer's state directory "
                           "from a backup as a whole (decision 0019)")
            return
        self._hold()
        try:
            store = SqliteStore(db, self.public_key(), mark["realm"])
        except L.StoreRefused as e:
            self.broken = f"the signer's replica does not open: {e}; restore the signer's state from a backup (decision 0019)"
            return
        self.replica = store
        try:
            replay.verify(store, self.public_key(), mark["realm"])
        except L.StoreRefused as e:
            self.broken = f"the signer's replica failed verification: {e}; restore the signer's state from a backup (decision 0019)"
            return
        cp = store.checkpoint()
        cp_size = L.open_checkpoint(cp, self.public_key())["size"] if cp else 0
        if store.size() > cp_size:                # a crash between a link and its checkpoint: the chain is verified
            store.add_checkpoint(L.seal_checkpoint(self.key, store.realm, store.size(), store.root(), store.head(),
                                                   self.FENCE, _now()))
            cp_size = store.size()
        if cp_size < mark["size"] or (mark["size"] and L.open_link(store.link(mark["size"] - 1),
                                                                    self.public_key())[1].hex() != mark["head"]):
            self.broken = (f"the replica's newest checkpoint covers {cp_size} links, but this signer last signed "
                           f"{mark['size']} (revision {mark['revision']}): a replica restored from an older backup must not "
                           "sign on top of a newer history. Restore the newest backup of the signer's state, or follow "
                           "the restore procedure (decision 0019)")

    def close(self) -> None:
        if self.replica is not None:
            self.replica.close()
        if self._held is not None:
            self._held.close()

    def _readable(self):
        """The replica for reading: served while signing is frozen (a desk keeps following, read-only, and says why),
        never while it is broken (a replica that failed verification is not read from)."""
        if self.broken and self.broken != self.frozen():
            raise SignerRefused(self.broken)
        if self.replica is None:
            raise SignerRefused("this signer keeps no change log yet: migrate its last signed revision first (op migrate)")
        return self.replica

    def _ready(self):
        if self.broken:
            raise SignerRefused(self.broken)
        if self.replica is None:
            raise SignerRefused("this signer keeps no change log yet: migrate its last signed revision first (op migrate)")
        return self.replica

    def public_key(self) -> str:
        return self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    # --- what it holds: the last revision it signed --------------------------------------------------------------

    def _last(self) -> tuple[int, str | None, str | None]:
        f = self.state / "last.json"
        if not f.exists():
            return 0, None, None
        v = json.loads(f.read_text(encoding="utf-8"))
        raw = (self.state / "last.yaml").read_text(encoding="utf-8")
        if _sha(raw.encode("utf-8")) != v["sha256"]:
            raise SignerRefused("the signer's own copy of the last revision changed: restore the signer's state")
        return int(v["revision"]), v["sha256"], raw

    def _keep(self, revision: int, raw: str) -> None:
        for name, data in (("last.yaml", raw), ("last.json", json.dumps({"revision": revision, "sha256": _sha(raw.encode("utf-8"))}))):
            tmp = self.state / (name + ".tmp")
            tmp.write_text(data, encoding="utf-8", newline="\n")
            os.replace(tmp, self.state / name)

    # --- signing ---------------------------------------------------------------------------------------------------

    def _line_sig(self, body: dict) -> str:
        b = {k: v for k, v in body.items() if k not in ("sha256", "signature")}
        sha = hashlib.sha256(json.dumps(b, sort_keys=True).encode()).hexdigest()
        if body.get("sha256") != sha:
            raise SignerRefused("the log line's hash does not match its body")
        return self.key.sign(sha.encode()).hex()

    def sign_line(self, body: dict) -> str:
        if not isinstance(body, dict) or "records_sha256" in body:
            raise SignerRefused("a line that vouches for a revision is signed only with its commit")
        return self._line_sig(body)

    def _refuse(self, old: dict, new: dict, fresh_errors, ops: list[dict] | None = None) -> None:
        """Why new may not follow old, as SignerRefused. The same rules for a YAML commit and for a proposed change:
        the history guard (over the touched records when the ops are known: scope.guard_errors, exactly the same), no
        new engine check error (fresh_errors() gives them, full or scoped), approval and proposer proofs."""
        from keyclerk import approvals, records, scope
        rewritten = records.guard(old, new) if ops is None else scope.guard_errors(old, new, ops)
        if rewritten:
            raise SignerRefused("history rewritten: " + "; ".join(rewritten[:3]))
        fresh = fresh_errors()
        if fresh:
            raise SignerRefused("the engine's checks refuse it: " + "; ".join(fresh[:3]))
        if self.proofs is not None:
            if self.replica is not None:              # decision 0028: proofs name internal anchors on the change log
                from keyclerk import anchors
                self.proofs.resolve = lambda claims, view=self.replica: anchors.resolve(view, claims)
            pol = self.proofs.policy
            added = sorted(set(approvals.check(new, self.proofs, pol)) - set(approvals.check(old, self.proofs, pol)))
            if added:
                raise SignerRefused("an approval without a valid proof: " + "; ".join(added[:3]))
            unsigned = approvals.check_proposals(old, new, self.proofs, pol)     # decision 0015: proposer proofs
            if unsigned:
                raise SignerRefused("a high-risk change without its proposer's signature: " + "; ".join(unsigned[:3]))

    def _judged(self, old_view, view, ops: list[dict], revision: int):
        """(old records, new records, a function giving the new engine errors) for a change, both states judged at the
        moment set: on the working set of what the change reaches (decision 0022 S4), or on the whole records when it
        reaches everyone, its reach cannot be computed, its working set is too wide, the configuration is not yet
        checked, or the signer runs with --full-check; every fallback is counted by its reason."""
        from keyclerk import metrics, scope
        from keyclerk.reconcile import check_records
        from keyclerk.store import replay
        from keyclerk.store.working import fresh_errors, scoped_judgement
        if old_view.size() == 0:                  # a log's first change (op start): judged whole against nothing, as
            new = {**replay.records(view), "revision": 1}         # the YAML path judges a first revision
            metrics.inc("keyclerk_check_fallback_total", reason="first")
            return {}, new, lambda: sorted(_norm(check_records(new, log_backed=True)))
        if self.full_check:
            r = scope.Full("forced")
        elif self.config_pending:
            r = scope.Full("config")              # a configuration not yet checked: in full until a background run
        else:
            got = scoped_judgement(old_view, view, ops, revision)
            if not isinstance(got, scope.Full):
                old, new, reach = got
                return old, new, lambda: sorted(fresh_errors(old, new, reach, ops))
            r = got
        metrics.inc("keyclerk_check_fallback_total", reason=r.reason)
        from keyclerk import records
        old, new = replay.records(old_view), {**replay.records(view), "revision": revision + 1}
        bad = records.validate(old, log_backed=True)
        if bad:                                   # the full check stops at schema errors, and the old and new states
            raise SignerRefused(                  # would share them: nothing else would be judged. Fail closed.
                f"the replica's records do not meet this engine's records schema ({bad[0][:160]}): the full check "
                "cannot judge a change on them. Run the records migration for this engine version, or roll the engine back")
        return old, new, lambda: sorted(_norm(check_records(new, log_backed=True)) - _norm(check_records(old, log_backed=True)))

    def commit(self, raw: str, body: dict) -> dict:
        """Check a new revision against the last one signed; sign its records and the log line that vouches for it."""
        from keyclerk import records
        from keyclerk.reconcile import check_records
        with self.lock:
            if self.replica is not None or self.broken:
                mark = self._mark() or {}
                raise SignerRefused(f"this signer keeps the change log since revision {mark.get('revision', '?')}: "
                                    "propose changes (decision 0022)")
            rb = raw.encode("utf-8")
            if body.get("records_sha256") != _sha(rb):
                raise SignerRefused("the log line names other records than the ones to sign")
            new = records.loads(raw)
            rev, _, last_raw = self._last()
            if new.get("revision") != rev + 1 or body.get("revision") != rev + 1:
                raise SignerRefused(f"revision {new.get('revision')} after {rev}: a revision is exactly one higher than the last signed")
            if last_raw is not None:
                old = records.loads(last_raw)
                self._refuse(old, new, lambda: sorted(_norm(check_records(new)) - _norm(check_records(old))))
            else:                                 # the first revision: judged like any change, against nothing
                try:
                    self._refuse(_empty(new), new, lambda: sorted(_norm(check_records(new))))
                except SignerRefused as e:
                    raise SignerRefused(f"the first revision is refused, nothing was signed: {e}") from None
            line = self._line_sig(body)
            sig = self.key.sign(rb).hex()
            self._keep(rev + 1, raw)
            return {"records_signature": sig, "line_signature": line}

    def adopt(self, raw: str, signature_hex: str) -> int:
        """Take over a store that signed in its own process: its current records, under this key's own signature,
        become the last revision signed. Only once: a signer that has signed refuses."""
        from cryptography.exceptions import InvalidSignature
        from keyclerk import records
        with self.lock:
            if (self.state / "last.json").exists():
                raise SignerRefused("this signer already holds a revision")
            try:
                self.key.public_key().verify(bytes.fromhex(signature_hex.strip()), raw.encode("utf-8"))
            except (InvalidSignature, ValueError):
                raise SignerRefused("these records are not signed with this key") from None
            rev = int(records.loads(raw).get("revision") or 0)
            self._keep(rev, raw)
            return rev

    # --- the change log (decision 0022 S3) --------------------------------------------------------------------------

    def migrate(self) -> dict:
        """Once: this signer's own last signed YAML revision (never one from the desk, which could hand it a false
        state) becomes the genesis and migrate links of its replica, proven at link k; the records key never leaves
        this process."""
        from keyclerk import records
        from keyclerk.store import link as L
        from keyclerk.store import migrate as M
        from keyclerk.store.sqlite import SqliteStore
        with self.lock:
            if self.replica is not None or self.broken or (self.state / "replica.db").exists():
                raise SignerRefused(self.broken or "this signer already keeps a change log: it migrates once")
            _, _, raw = self._last()
            if raw is None:
                raise SignerRefused("this signer holds no signed revision to migrate: adopt the desk store first (--adopt)")
            from keyclerk.reconcile import check_records
            errors = check_records(records.loads(raw))
            if errors:                            # the genesis is judged too, not only its signature proven
                from keyclerk import remedies
                steps = "\n".join(f"  - {e}\n    fix: {remedies.match(e)[1]}" for e in errors[:50])
                more = f"\n  ... and {len(errors) - 50} more" if len(errors) > 50 else ""
                raise SignerRefused(f"the revision to migrate does not pass the engine's checks, nothing was signed. "
                                    f"Fix each with an ordinary change on the YAML store, then migrate "
                                    f"({len(errors)} in all):\n{steps}{more}")
            self._hold()
            db = self.state / "replica.db"
            store = None
            try:
                store = SqliteStore(db, self.public_key(), records.loads(raw)["realm"])
                M.migrate_yaml(raw, self.key.sign(raw.encode("utf-8")).hex(), self.key, store, _now())
            except BaseException as e:
                if store is not None:
                    store.close()
                for suffix in ("", "-wal", "-shm"):
                    Path(str(db) + suffix).unlink(missing_ok=True)
                self._held.close()
                self._held = None
                if isinstance(e, L.StoreRefused):
                    raise SignerRefused(f"the migration was refused: {e}") from None
                raise
            self.replica = store
            self._write_mark()
            self.config_pending = True            # judged in full until the first background full check passes
            return self._head()

    def start(self, realm: str) -> dict:
        """Once, for a deployment with no signed YAML revision to migrate (init seeding onto the change log): an empty
        replica. The first proposal becomes link 0, judged in full against an empty state like every change after it."""
        from keyclerk import guard
        from keyclerk.store.sqlite import SqliteStore
        with self.lock:
            if self.replica is not None or self.broken or (self.state / "replica.db").exists():
                raise SignerRefused(self.broken or "this signer already keeps a change log: it starts once")
            if self._last()[2] is not None:
                raise SignerRefused("this signer holds a signed YAML revision: migrate it (op migrate), so its history "
                                    "is kept, instead of starting an empty log")
            try:
                guard.name(realm, "realm")
            except Exception as e:
                raise SignerRefused(f"start: {e}") from None
            self._hold()
            self.replica = SqliteStore(self.state / "replica.db", self.public_key(), realm)
            self._write_mark()
            self.config_pending = True            # judged in full until the first background full check passes
            return self._head()

    def _head(self) -> dict:
        from keyclerk.store import replay
        r = self.replica
        return {"size": r.size(), "head": r.head().hex() if r.head() else None, "root": r.root().hex(), "fence": self.FENCE,
                "revision": replay.revision(r), "checkpoint": r.checkpoint(), "migration": r.migration()}

    def head(self) -> dict:
        frozen = self.frozen() if self.broken else None
        if self.broken and self.broken != frozen:
            return {"broken": self.broken}
        if self.replica is None:
            return {"size": 0, "migrated": False}
        with self.lock:
            return {**self._head(), **({"frozen": frozen} if frozen else {})}

    DUPLICATE_WINDOW = 1000                       # links after a stale base searched for the same change

    def propose(self, base: dict, change: dict, tokens: list, rows: list | None = None) -> dict:
        """Apply a change to the replica in one transaction, check it there against the replica's own state, and only
        then sign and keep it, with its per-change checkpoint (decision 0022 point 5). The desk's base is a staleness guard, never state.
        The key signs nothing for a refused change: the unsigned body is checked, and sealed only once it passed."""
        from keyclerk.store import link as L
        from keyclerk.store import replay
        with self.lock:
            store = self._ready()
            if self.not_ready:
                raise SignerRefused(self.not_ready)
            size, head = store.size(), store.head()
            hexhead = head.hex() if head is not None else None
            if not isinstance(base, dict) or base.get("size") != size or base.get("head") != hexhead:
                dup = self._duplicate(store, base, change)
                if dup is not None:
                    return dup
                raise SignerRefused(f"stale: the signer's head is {size}/{hexhead}; resync and propose again")
            if not isinstance(change, dict) or set(change) != {"ops", "entry"}:
                raise SignerRefused("a change is exactly ops and entry")
            _entry_shape(change["entry"])
            per_kind: dict[str, int] = {}
            for op in change["ops"] if isinstance(change["ops"], list) else []:
                k = op.get("kind") if isinstance(op, dict) else None
                per_kind[k] = per_kind.get(k, 0) + 1
            wide = sorted(k for k, n in per_kind.items() if n > self.MAX_PER_KIND)
            if wide:
                raise SignerRefused(f"a change touches more than {self.MAX_PER_KIND} records of {', '.join(map(str, wide))}: "
                                    "split it into smaller changes (the per-change cap, decision 0022)")
            self._no_provider_ids(change["ops"], store)
            side = self._tokens(change["ops"], tokens) + self._rows(store, change["ops"], rows)
            try:
                body = L.link_body(store.realm, size, hexhead or L.ZERO, self.FENCE, _now(), change["ops"],
                                   change["entry"])
            except (L.StoreRefused, TypeError, KeyError) as e:
                raise SignerRefused(f"not a change the log can carry: {e}") from None
            from keyclerk import clock
            moment = clock.now()                      # old and new judged at one moment (decision 0022 S4): the checks
            ops = body["change"]["ops"]               # read the clock, so errors kept from an earlier change could mask
            old_view = store.reader()                 # a new one; the old state read on a connection of its own
            try:
                revision = replay.revision(old_view) or 0

                def check(view):                  # the replica with the change applied, before anything is signed
                    with clock.at(moment):
                        old, new, fresh = self._judged(old_view, view, ops, revision)
                        self._refuse(old, new, fresh, ops)
                sealed, h = store.append_checked(body, lambda b: L.seal_body(self.key, b), side=side, check=check)
            except L.StoreRefused as e:
                raise SignerRefused(str(e)) from None
            finally:
                old_view.close()
            cp = L.seal_checkpoint(self.key, store.realm, store.size(), store.root(), h, self.FENCE, _now())
            store.add_checkpoint(cp)
            self._write_mark()
            return {"link": sealed, "checkpoint": cp, "hash": h.hex(), "root": store.root().hex(),
                    "revision": replay.revision(store)}

    def _duplicate(self, store, base, change) -> dict | None:
        """A change proposed again after its answer was lost: the desk's base is stale only because this very change
        was applied. Found by its change_id among the links after the base, on the same history, with the same ops and
        entry, it is answered with the link it already is; the same change_id with another change is refused."""
        from keyclerk.store import link as L
        if not (isinstance(base, dict) and isinstance(change, dict) and isinstance(change.get("entry"), dict)
                and isinstance(change.get("ops"), list)):
            return None
        cid, at = change["entry"].get("change_id"), base.get("size")
        if not isinstance(cid, str) or not isinstance(at, int) or isinstance(at, bool) or not 0 <= at < store.size():
            return None
        prev = L.open_link(store.link(at - 1), self.public_key())[1].hex() if at else None
        if prev != base.get("head"):
            return None                               # another history: an ordinary stale refusal
        try:
            ops = sorted(change["ops"], key=lambda o: (o["kind"], o["key"]))
        except (KeyError, TypeError):
            return None
        for seq in range(at, min(store.size(), at + self.DUPLICATE_WINDOW)):
            sealed = store.link(seq)
            body, h = L.open_link(sealed, self.public_key())
            if body["change"]["entry"].get("change_id") != cid:
                continue
            if body["change"]["ops"] != ops or body["change"]["entry"] != change["entry"]:
                raise SignerRefused(f"change {cid[:40]} is already link {seq}, with other contents: a change id names "
                                    "one change; give a new change a new id")
            return {"duplicate": seq, "link": sealed, "checkpoint": store.checkpoint(seq + 1), "hash": h.hex()}
        return None

    @staticmethod
    def _no_provider_ids(ops, store) -> None:
        """Decision 0028: a link names people by internal anchors only, each an account of the log (an accounts record
        already kept, or put by the same change). A record that names a person by the identity provider's id, or by an
        internal anchor no account stands for, is refused, whatever the desk meant."""
        from keyclerk import anchors as A
        from keyclerk import records as R
        fresh = {op.get("key") for op in ops if isinstance(op, dict) and op.get("kind") == "accounts"} \
            if isinstance(ops, list) else set()
        for op in ops if isinstance(ops, list) else []:
            if not (isinstance(op, dict) and op.get("op") == "put" and isinstance(op.get("record"), dict)):
                continue
            kind, recs = op.get("kind"), [op["record"]]
            if kind == "head":                    # a head field: the root, the connected organisations
                kind, value = op.get("key"), op["record"].get("value")
                recs = value if isinstance(value, list) else [value]
            for rec in recs:
                for path, v in R.anchor_values(kind, rec) if isinstance(rec, dict) else ():
                    if A.is_person(v) and not A.is_internal(v):
                        raise SignerRefused(f"{kind} {str(op.get('key'))[:40]}: {path} names a person by {v[:40]!r}, not "
                                            "by an internal anchor (decision 0028): the desk translates at its boundary")
                    if A.is_internal(v) and v not in fresh and store.get("accounts", v) is None:
                        raise SignerRefused(f"{kind} {str(op.get('key'))[:40]}: {path} names {v}, which is no account of "
                                            "the log: an account enters with its accounts record and mapping row")

    @staticmethod
    def _rows(store, ops, rows) -> list[tuple[str, str, dict]]:
        """Mapping rows for the accounts a change brings in (decision 0028): an account enters as an accounts record,
        {anchor, commit}, with its mapping row in the same change, the row matching the commit. An accounts record never
        changes once in the log (a new commit would re-point the anchor) and leaves only by erasure; so a desk can never
        re-point an anchor or give an account a second one."""
        from keyclerk import anchors as A
        if rows is not None and (not isinstance(rows, list) or len(rows) > 500):
            raise SignerRefused("rows are a list of at most 500 mapping rows")
        vouched: dict[str, set] = {}
        for op in ops if isinstance(ops, list) else []:
            if not isinstance(op, dict) or op.get("kind") != "accounts":
                continue
            if op.get("op") != "put":
                raise SignerRefused(f"accounts {str(op.get('key'))[:40]}: an account leaves the log only by erasure")
            was = store.get("accounts", op.get("key"))
            if was is not None:
                if was != op.get("record"):
                    raise SignerRefused(f"accounts {str(op.get('key'))[:40]}: an account's commitment never changes")
                continue
            vouched[op["key"]] = {op["record"].get("commit")} if isinstance(op.get("record"), dict) else set()
        given = {r.get("anchor") for r in rows or [] if isinstance(r, dict)}
        for anchor in vouched:
            if anchor not in given:
                raise SignerRefused(f"accounts {anchor[:40]}: an account enters with its mapping row")
        rows = rows or []
        out, seen = [], set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("anchor"), str) or not isinstance(row.get("idp"), str)                     or not set(row) <= {"anchor", "idp", "salt", "label"}:
                raise SignerRefused("a mapping row is {anchor, idp, salt, label?}: a broker subject is linked only later, "
                                    "by the reconciler")
            anchor, idp = row["anchor"], row["idp"]
            if idp.startswith("sub:"):                  # the reverse table keys subjects as "sub:" + subject
                raise SignerRefused(f"mapping row {anchor[:40]}: an identity provider id never starts with sub:")
            if not A.row_matches(row, vouched.get(anchor)):
                raise SignerRefused(f"mapping row {anchor[:40]}: no accounts record this change puts carries its "
                                    "commitment")
            if anchor in seen or store.side_get("anchor_map", anchor) is not None:
                raise SignerRefused(f"mapping row {anchor[:40]}: the anchor is mapped already")
            if store.side_get("anchor_idp", A.idp_key(idp)) is not None or A.idp_key(idp) in seen:
                raise SignerRefused(f"mapping row {anchor[:40]}: that account has an anchor already")
            seen.update((anchor, A.idp_key(idp)))
            out += [("anchor_map", anchor, row), ("anchor_idp", A.idp_key(idp), {"anchor": anchor})]
        return out

    @staticmethod
    def _tokens(ops, tokens) -> list[tuple[str, str, dict]]:
        """The proof tokens of a change, each for a proof the change itself puts, under its own hash."""
        if not isinstance(tokens, list):
            raise SignerRefused("tokens are a list of [sha256, token]")
        proofs = {op.get("key") for op in ops if isinstance(op, dict) and op.get("op") == "put"
                  and op.get("kind") in ("approval_proofs", "proposal_proofs")} if isinstance(ops, list) else set()
        out = []
        for t in tokens:
            if not (isinstance(t, list) and len(t) == 2 and all(isinstance(x, str) for x in t)) or _sha(t[1].encode()) != t[0]:
                raise SignerRefused("a token is [its sha256, the token]")
            if len(t[1]) > 16384:                 # the records schema's bound on a proof's token
                raise SignerRefused("a proof's token is at most 16384 characters")
            if t[0] not in proofs:
                raise SignerRefused("a token for no proof this change puts")
            out.append(("proof_tokens", t[0], {"token": t[1]}))
        return out

    def links(self, start: int, limit: int) -> dict:
        store = self._readable()
        if not (isinstance(start, int) and isinstance(limit, int) and start >= 0 and 1 <= limit <= 500):
            raise SignerRefused("links: start from 0, limit 1 to 500")
        with self.lock:
            return {"links": list(store.links(start, start + limit)), "size": store.size()}

    def tokens(self, after: str | None, limit: int) -> dict:
        """The proof tokens, for a desk that lost its store: bounded, and every call a signed line in the audit log."""
        store = self._readable()
        if not (after is None or isinstance(after, str)) or not (isinstance(limit, int) and 1 <= limit <= 500):
            raise SignerRefused("tokens: after a sha256 or null, limit 1 to 500")
        with self.lock:
            out = [[k, r["token"]] for k, r in store.side_scan("proof_tokens") if after is None or k > after][:limit]
            self._audit({"op": "tokens", "after": after, "count": len(out)})
            return {"tokens": out}

    def anchors(self, after: str | None, limit: int) -> dict:
        """The mapping rows (decision 0028), for a desk that migrates or lost its store: bounded, and every call a
        signed line in the audit log, as with tokens (the rows link internal anchors to people)."""
        store = self._readable()
        if not (after is None or isinstance(after, str)) or not (isinstance(limit, int) and 1 <= limit <= 500):
            raise SignerRefused("anchors: after an internal anchor or null, limit 1 to 500")
        with self.lock:
            out = [[k, r] for k, r in store.side_scan("anchor_map") if after is None or k > after][:limit]
            self._audit({"op": "anchors", "after": after, "count": len(out)})
            return {"anchors": out}

    def link_subject(self, anchor: str, sub: str) -> dict:
        """Phase 2 of decision 0028 (the reconciler, which sees the broker's user ids): a mapping row learns the broker
        subject of its account, once. From then on sign-in, proofs and the reconciler know the person by that subject
        only. A row linked to another subject, or a subject linked to another anchor, is refused: a moved account is an
        incident for the security officer, never a silent re-link. Every link is a signed line in the audit log."""
        from keyclerk import anchors as A
        from keyclerk import guard
        store = self._ready()
        try:
            sub = guard.uuid(sub, "subject")
        except Exception as e:
            raise SignerRefused(f"link_subject: {e}") from None
        with self.lock:
            row = store.side_get("anchor_map", anchor) if isinstance(anchor, str) else None
            if row is None:
                raise SignerRefused("link_subject: no mapping row for that anchor (erased, or never an account)")
            if row.get("sub") == sub:
                return {"linked": False}
            if row.get("sub"):
                raise SignerRefused(f"link_subject: {anchor[:40]} is linked to another subject already: a moved account "
                                    "is for the security officer")
            taken = store.side_get("anchor_idp", A.sub_key(sub))
            if taken is not None:
                raise SignerRefused("link_subject: that subject is linked to another anchor")
            store.side_put("anchor_map", anchor, {**row, "sub": sub})
            store.side_put("anchor_idp", A.sub_key(sub), {"anchor": anchor})
            self._audit({"op": "link_subject", "anchor": anchor})
            return {"linked": True}

    def checkpoint(self, size: int | None) -> dict:
        store = self._readable()
        with self.lock:
            cp = store.checkpoint(size)
        if cp is None:
            raise SignerRefused(f"no checkpoint at {size} links")
        return {"checkpoint": cp}

    def _audit(self, what: dict) -> None:
        """A signed line in state/audit.jsonl, chained to the one before, for every read of bearer-ish material."""
        f = self.state / "audit.jsonl"
        prev = getattr(self, "_audit_prev", None)
        if prev is None:                          # once per process: the last line's hash, from the file's tail
            prev = "0" * 64
            if f.exists() and f.stat().st_size:
                with f.open("rb") as h:
                    h.seek(max(0, f.stat().st_size - 4096))
                    prev = json.loads(h.read().splitlines()[-1])["sha256"]
        body = {"at": _now(), "prev": prev, **what}
        body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["signature"] = self._line_sig(body)
        with f.open("a", encoding="utf-8", newline="\n") as h:
            h.write(json.dumps(body, sort_keys=True) + "\n")
        self._audit_prev = body["sha256"]


def _empty(new: dict) -> dict:
    """The state before a first revision: nothing, in the records' shape."""
    return {"realm": new.get("realm"), "grants": [], "revocations": [], "suspensions": []}


def _now() -> str:
    from datetime import datetime, timezone
    from keyclerk import edge as E
    return datetime.now(timezone.utc).strftime(E.ISO)


# --- the socket ------------------------------------------------------------------------------------------------------

_ENTRY_ID = re.compile(r"C-[0-9a-z-]{1,40}")
_ENTRY_WORD = re.compile(r"[a-z_]{1,40}")
_ENTRY_SUMMARY = re.compile(r"[a-z_]{1,40} on [A-Za-z0-9_:, -]{0,400}")    # the desk's "<action> on <visit ids>"


def _entry_shape(entry) -> None:
    """A link keeps an entry's structure, never its free text (decision 0028): the desk's LINK_ENTRY fields, each in
    its shape, checked here because the signed log is kept for good and no erasure reaches it."""
    if not isinstance(entry, dict) or not set(entry) <= {"change_id", "action", "actor", "outcome", "records", "summary"}:
        raise SignerRefused("an entry is change_id, action, actor, outcome and records (and a visit's summary) only")
    from keyclerk import anchors as A
    checks = [("change_id", lambda v: isinstance(v, str) and _ENTRY_ID.fullmatch(v)),
              ("action", lambda v: isinstance(v, str) and _ENTRY_WORD.fullmatch(v)),
              ("outcome", lambda v: isinstance(v, str) and _ENTRY_WORD.fullmatch(v)),
              ("actor", lambda v: v is None or A.is_internal(v) or (isinstance(v, str) and v.startswith("keyclerk:")
                                                                     and _ENTRY_WORD.fullmatch(v[9:]))),
              ("summary", lambda v: isinstance(v, str) and _ENTRY_SUMMARY.fullmatch(v)),
              ("records", lambda v: isinstance(v, dict) and all(_ENTRY_WORD.fullmatch(str(k)) and isinstance(x, list)
                                                                for k, x in v.items()))]
    for key, ok in checks:
        if key in entry and not ok(entry[key]):
            raise SignerRefused(f"entry {key}: not in its shape (an internal anchor, an id, a word), never free text")


# Who may ask what (decision 0028, amendment of 2026-10-26): a subject link is never undone and decides whose sign-ins
# count as whom, so only the reconciler, which reads the broker, records one; the desk's credential cannot.
READ_OPS = frozenset({"ping", "public_key", "head", "links", "anchors", "checkpoint"})
ROLE_OPS = {"desk": READ_OPS | {"sign_line", "commit", "migrate", "propose", "start", "tokens"},
            "reconciler": READ_OPS | {"link_subject"}}


def _handler(signer: Signer, token: str | None, role: str = "desk"):
    allowed = ROLE_OPS[role]

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(MAX_REQUEST + 1)
            try:
                req = json.loads(line)
                if token is not None and not hmac.compare_digest(str(req.get("token", "")), token):
                    raise SignerRefused(f"not the {role}: wrong token")
                op = req.get("op")
                if op == "link_subject" and op not in allowed:
                    raise SignerRefused("a subject link comes only from the reconciler, on its own listener")
                if op not in allowed:
                    raise SignerRefused(f"not the {role}'s to ask" if op in ROLE_OPS["desk"] | ROLE_OPS["reconciler"]
                                        else "unknown op")
                if op == "ping":                                 # liveness (decision 0018): answers, signs nothing
                    out = {"ok": False, "broken": signer.broken} if signer.broken else \
                        {"ok": False, "not_ready": signer.not_ready} if signer.not_ready else {"ok": True}
                elif op == "public_key":
                    out = {"key": signer.public_key()}
                elif op == "sign_line":
                    out = {"signature": signer.sign_line(req["body"])}
                elif op == "commit":
                    out = signer.commit(req["raw"], req["body"])
                elif op == "migrate":                            # decision 0022 S3: the change log
                    out = signer.migrate()
                elif op == "head":
                    out = signer.head()
                elif op == "propose":
                    out = signer.propose(req.get("base"), req.get("change"), req.get("tokens", []), req.get("rows"))
                elif op == "start":                              # a log that begins empty (init seeding)
                    out = signer.start(req.get("realm"))
                elif op == "links":
                    out = signer.links(req.get("start"), req.get("limit"))
                elif op == "tokens":
                    out = signer.tokens(req.get("after"), req.get("limit"))
                elif op == "anchors":
                    out = signer.anchors(req.get("after"), req.get("limit"))
                elif op == "checkpoint":
                    out = signer.checkpoint(req.get("size"))
                elif op == "link_subject":                       # the reconciler, phase 2 (decision 0028)
                    out = signer.link_subject(req.get("anchor"), req.get("sub"))
                else:
                    raise SignerRefused("unknown op")
            except SignerRefused as e:
                out = {"refused": str(e)}
            except Exception as e:   # noqa: BLE001 - the desk sees a refusal, never a trace
                out = {"refused": f"{type(e).__name__}: {str(e)[:200]}"}
            self.wfile.write((json.dumps(out) + "\n").encode())
    return H


class _TCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(signer: Signer, listen: str, token: str | None, role: str = "desk"):
    """One listener per role: the desk's, and the reconciler's (its own socket path or port and its own token)."""
    if listen.startswith("unix:"):
        path = listen[5:]
        if os.path.exists(path):
            os.unlink(path)
        srv = socketserver.ThreadingUnixStreamServer(path, _handler(signer, None, role))   # file permissions are the guard
        os.chmod(path, 0o600)
    elif listen.startswith("tcp:"):
        host, port = listen[4:].rsplit(":", 1)
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise SystemExit("the signer listens on loopback only")
        if not token:
            raise SystemExit("over TCP the signer needs --token")
        srv = _TCP((host, int(port)), _handler(signer, token, role))
    else:
        raise SystemExit("--listen unix:/path or tcp:127.0.0.1:port")
    return srv


class SignerClient:
    """What the desk's store calls instead of holding the records key."""

    def __init__(self, address: str, token_file: str | None = None):
        self.address = address
        self.token = Path(token_file).read_text(encoding="utf-8").strip() if token_file else None

    def _call(self, req: dict) -> dict:
        from keyclerk import metrics
        op = str(req.get("op"))
        try:
            with metrics.timed("keyclerk_signer_seconds", op=op):
                return self._call_raw(req)
        except Exception:
            metrics.inc("keyclerk_signer_errors_total", op=op)
            raise

    def _call_raw(self, req: dict) -> dict:
        if self.token:
            req = {**req, "token": self.token}
        if self.address.startswith("unix:"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.address[5:])
        else:
            host, port = self.address[4:].rsplit(":", 1)
            s = socket.create_connection((host, int(port)), timeout=30)
        with s:
            s.sendall((json.dumps(req) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        out = json.loads(data or b"{}")
        if "refused" in out:
            raise SignerRefused(out["refused"])
        return out

    def ping(self) -> None:
        out = self._call({"op": "ping"})
        if out.get("ok") is not True:
            raise SignerRefused(out.get("broken") or out.get("not_ready") or "the signer did not answer ping")

    def public_key(self) -> str:
        return self._call({"op": "public_key"})["key"]

    def sign_line(self, body: dict) -> str:
        return self._call({"op": "sign_line", "body": body})["signature"]

    def commit(self, raw: str, body: dict) -> dict:
        return self._call({"op": "commit", "raw": raw, "body": body})

    # --- the change log (decision 0022 S3) ---

    def migrate(self) -> dict:
        return self._call({"op": "migrate"})

    def head(self) -> dict:
        return self._call({"op": "head"})

    def propose(self, base: dict, change: dict, tokens: list | None = None, rows: list | None = None) -> dict:
        return self._call({"op": "propose", "base": base, "change": change, "tokens": tokens or [],
                           **({"rows": rows} if rows else {})})

    def start(self, realm: str) -> dict:
        return self._call({"op": "start", "realm": realm})

    def links(self, start: int, limit: int = 500) -> dict:
        return self._call({"op": "links", "start": start, "limit": limit})

    def tokens(self, after: str | None = None, limit: int = 500) -> dict:
        return self._call({"op": "tokens", "after": after, "limit": limit})

    def anchors(self, after: str | None = None, limit: int = 500) -> dict:
        return self._call({"op": "anchors", "after": after, "limit": limit})

    def checkpoint(self, size: int | None = None) -> dict:
        return self._call({"op": "checkpoint", "size": size})

    def link_subject(self, anchor: str, sub: str) -> dict:
        return self._call({"op": "link_subject", "anchor": anchor, "sub": sub})


def resume_main(argv: list[str]) -> int:
    """python -m keyclerk.signer resume --key KEY --state DIR --config FILE --by NAME --reason TEXT [--accept-baseline]

    Ends a freeze of signing (decision 0022 S4), at the signer's terminal with the signer stopped: it needs the records
    key (which signs the resume line in the audit log) and a terminal, never a script or a file edit."""
    ap = argparse.ArgumentParser(prog="python -m keyclerk.signer resume", description=resume_main.__doc__.splitlines()[0])
    ap.add_argument("--key", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--by", required=True, help="who resumes (a name the audit log keeps)")
    ap.add_argument("--reason", required=True, help="why it is safe to resume (kept in the audit log)")
    ap.add_argument("--accept-baseline", action="store_true",
                    help="the current state becomes the background check's baseline (otherwise the next run compares "
                         "against the last state that passed, and freezes again if nothing was fixed)")
    a = ap.parse_args(argv)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SystemExit("keyclerk.signer resume: refused: a resume runs at the signer's terminal (a TTY), by an operator "
                         "who holds the records key; run it there, with the signer stopped")
    from keyclerk import config, guard
    config.configure(a.config)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(a.key), 200).strip()))
    try:
        signer = Signer(key, Path(a.state))
    except SignerRefused as e:
        raise SystemExit(f"keyclerk.signer resume: refused: {e}") from None
    try:
        why = signer.frozen()
        if why is None:
            raise SystemExit("keyclerk.signer resume: signing is not frozen: there is nothing to resume")
        sys.stdout.write(f"{why}\nType 'resume' to end this freeze as {a.by}"
                         f"{', accepting the current state as the baseline' if a.accept_baseline else ''}: ")
        sys.stdout.flush()
        if sys.stdin.readline().strip() != "resume":
            raise SystemExit("keyclerk.signer resume: not resumed")
        line = signer.resume(a.by, a.reason, a.accept_baseline)
        sys.stdout.write(f"resumed, signed in the audit log: {json.dumps(line)}\n")
    except SignerRefused as e:
        raise SystemExit(f"keyclerk.signer resume: refused: {e}") from None
    finally:
        signer.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["resume"]:
        return resume_main(argv[1:])
    ap = argparse.ArgumentParser(prog="python -m keyclerk.signer", description=__doc__.splitlines()[0])
    ap.add_argument("--key", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--listen", help="unix:/path or tcp:127.0.0.1:port; not needed with --adopt")
    ap.add_argument("--token")
    ap.add_argument("--reconciler-listen", help="the reconciler's own listener (unix:/path or tcp:127.0.0.1:port): the "
                                                "only one that records a broker subject (link_subject)")
    ap.add_argument("--reconciler-token", help="the reconciler's token file for a TCP listener; never the desk's")
    ap.add_argument("--approval-issuer", action="append", default=[])
    ap.add_argument("--approval-audience", action="append", default=[])
    ap.add_argument("--approval-jwks", help="the broker's published keys (its certs endpoint)")
    ap.add_argument("--full-check-hours", type=float, default=24.0,
                    help="hours between background full checks on a snapshot (one also runs at start)")
    ap.add_argument("--full-check", action="store_true",
                    help="judge every change by the full check, not scoped to what it reaches (the reference path)")
    ap.add_argument("--adopt", metavar="STORE", help="take over the current revision of this desk store, then exit")
    a = ap.parse_args(argv)
    from keyclerk import config, guard
    config.configure(a.config)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(a.key), 200).strip()))
    if a.adopt:
        st = Path(a.adopt)
        rev = Signer(key, Path(a.state)).adopt((st / "records.yaml").read_text(encoding="utf-8"),
                                               (st / "records.yaml.sig").read_text(encoding="ascii"))
        sys.stderr.write(f"keyclerk.signer: adopted revision {rev}\n")
        return 0
    proofs = None
    if (config.current().get("approvals") or {}).get("proofs") == "required" and not a.approval_issuer:
        raise SystemExit("approvals.proofs is required in the configuration, but no --approval-issuer is given: the "
                         "signer would check no proof. Pass --approval-issuer, --approval-audience and --approval-jwks")
    if a.approval_issuer:
        from keyclerk import approvals
        if not (a.approval_audience and a.approval_jwks):
            raise SystemExit("approval proofs need --approval-audience and --approval-jwks")
        policy = config.current().get("approvals") or {}
        proofs = approvals.BrokerProofs(a.approval_issuer, a.approval_audience, policy.get("max_age_seconds", 300),
                                        a.approval_jwks, Path(a.state) / "broker-keys.json", acr=policy.get("acr"))
        proofs.policy = policy
    if not a.listen:
        raise SystemExit("--listen unix:/path or tcp:127.0.0.1:port")
    token = Path(a.token).read_text(encoding="utf-8").strip() if a.token else None
    try:
        signer = Signer(key, Path(a.state), proofs, full_check=a.full_check)
    except SignerRefused as e:
        raise SystemExit(f"keyclerk.signer: {e}") from None
    if signer.broken:
        sys.stderr.write(f"keyclerk.signer: refusing to sign: {signer.broken}\n")
    if signer.replica is not None and not signer.broken:
        signer.start_background(a.full_check_hours * 3600)
    srv = serve(signer, a.listen, token)
    if a.reconciler_listen:
        rtoken = Path(a.reconciler_token).read_text(encoding="utf-8").strip() if a.reconciler_token else None
        if a.reconciler_listen == a.listen or (rtoken and token and hmac.compare_digest(rtoken, token)):
            raise SystemExit("the reconciler's listener and token are its own, never the desk's")
        rsrv = serve(signer, a.reconciler_listen, rtoken, role="reconciler")
        threading.Thread(target=rsrv.serve_forever, daemon=True).start()
        sys.stderr.write(f"keyclerk.signer: the reconciler's listener on {a.reconciler_listen}\n")
    sys.stderr.write(f"keyclerk.signer: listening on {a.listen}, key {signer.public_key()[:16]}...\n")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
