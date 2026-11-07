# SPDX-License-Identifier: EUPL-1.2
"""The reconciler: the one writer of the broker's managed groups.

A run applies a records revision only when it passes everything the engine knows:
1. one writer: a lock in the state directory, taken over only when its lease has run out;
2. the records and the configuration through the guard (bounded, no YAML aliases, identifiers and zoned times), the
   records schema and every engine check (grants, leases, delegation, places, situation); one failure and nothing is
   applied;
3. integrity: the records carry a detached Ed25519 signature by a key the deployment pins (--signing-key); unsigned
   records are applied only with --allow-unsigned (a local demo);
4. history: compared with the last applied revision, revocations only grow and ended records never change;
5. trust: with require_trust in the configuration, a group member without trust input stays dormant (absent trust is
   the strictest value: fail closed);
6. blast radius: a run that would remove more than the configured count or share of managed memberships stops,
   unless an override file in the state directory names that very plan;
7. it writes only with --apply (the default is a dry run), under an idempotency key that is the hash of the revision
   and the plan;
8. a logout that fails is queued and retried every run until it succeeds; its age is reported;
9. every run, failed or not, is one line in the run log (rotated), with its findings and the configuration's hash.
The broker's credentials are never kept: each run exchanges the client secrets (mounted files, or the vault where one
runs) for access tokens of a few minutes; the writer and the reader are separate clients.

    python -m keyclerk.reconcile --config keyclerk.yaml --records records.yaml --keycloak https://id.example \\
        --realm example --secret-file /run/secrets/writer --reader-client keyclerk-reader \\
        --reader-secret-file /run/secrets/reader --state /var/lib/keyclerk (--signing-key key.pub | --allow-unsigned)
        [--trust trust.yaml] [--apply] [--once] [--interval 60]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

from keyclerk import clock, config, grants, guard, leases, records
from keyclerk.connectors.keycloak import KeycloakTarget
from keyclerk.store.log_reconcile import LogRefused


class Refused(Exception):
    """A run that applies nothing, with a reason safe to log."""


# --- credentials --------------------------------------------------------------------------------------------------

def token(keycloak: str, realm: str, client: str, secret: str) -> str:
    """A short-lived access token for one of the reconciler's own clients (client credentials)."""
    guard.name(realm, "realm")
    guard.name(client, "client")
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client, "client_secret": secret}).encode()
    url = f"{guard.broker_url(keycloak)}/realms/{urllib.parse.quote(realm, safe='')}/protocol/openid-connect/token"
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=30) as r:
        body = guard.read_response(r)
    tok = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(tok, str) or len(tok) > 16384:
        raise Refused("the broker returned no usable token")
    return tok


def _secret(path: str) -> str:
    s = guard.read_bounded(Path(path), 4096).strip()
    if not s or any(c.isspace() for c in s):
        raise Refused("a client secret file is empty or malformed")
    return s


# --- the checks before anything is applied ------------------------------------------------------------------------

def verify_signature(raw: bytes, sig_path: Path, pub_path: Path) -> None:
    """A detached Ed25519 signature over the exact records bytes, by the pinned public key (raw 32 bytes, hex)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(guard.read_bounded(pub_path, 200).strip()))
        sig = bytes.fromhex(guard.read_bounded(sig_path, 400).strip())
        pub.verify(sig, raw)
    except (InvalidSignature, ValueError, FileNotFoundError) as e:
        raise Refused(f"records signature does not verify ({type(e).__name__})") from e


def check_records(doc: dict, log_backed: bool = False) -> list[str]:
    """Every engine check on a records revision; empty means it may be applied. Folded once per check (one check once
    folded the same memberships tens of thousands of times), judged at one moment (keyclerk.clock: the one already
    set, else now). log_backed: records kept one per row (the change log, decision 0022), judged without the schema's
    whole-document caps."""
    from keyclerk import delegation
    with clock.fixed(), delegation.memo():
        return _check_records(doc, log_backed)


def _check_records(doc: dict, log_backed: bool = False) -> list[str]:
    from keyclerk import delegation, places, situation
    errs = records.validate(doc, log_backed)
    if errs:
        return errs
    errs += records.duplicate_ids(doc)
    errs += grants.check(doc, grants.rules(), log_backed=log_backed)
    if doc.get("leases"):
        errs += leases.check(doc, leases.rules())
    if doc.get("groups"):
        errs += delegation.check(doc)
    if doc.get("places"):
        errs += places.check(doc)
    if doc.get("situations") or doc.get("surge_packages"):
        errs += situation.check(doc)
    if doc.get("visits") or doc.get("visit_events") or doc.get("badges"):
        from keyclerk import visits
        errs += visits.check(doc)
    if doc.get("edges") or doc.get("person_keys") or doc.get("edge_visit_leases") or doc.get("edge_rotations"):
        from keyclerk import edge_records
        errs += edge_records.check(doc)
    if doc.get("ha") is not None:                  # decision 0031: HA as signed realm configuration
        from keyclerk import ha
        errs += ha.check(doc)
    return errs


def load_trusts(path: str | None) -> dict | None:
    """keyclerk-trust-input-v1 documents, one per person, each validated against its schema."""
    if not path:
        return None
    import jsonschema
    doc = guard.load_yaml(Path(path)) or []
    items = doc if isinstance(doc, list) else doc.get("trust", [])
    v = jsonschema.Draft202012Validator(config.schema("trust-input"))
    out = {}
    for t in items:
        errs = list(v.iter_errors(json.loads(json.dumps(t, default=str))))
        if errs:
            raise Refused(f"trust input for {guard.safe_for_log(t.get('anchor', '?'), 60)} is invalid")
        out[guard.anchor(t["anchor"], "anchor")] = t
    return out


def desired(doc: dict, at: datetime, trusts: dict | None = None) -> set[tuple[str, str]]:
    """Every (group, anchor) membership the records require now; with require_trust and no trust input for a person,
    that person's group memberships stay dormant."""
    if trusts is None and config.current()["risk_port"].get("require_trust"):
        trusts = {}
    lease_groups = leases.schedule(doc, leases.rules(), at) if doc.get("leases") else {}
    p = grants.plan(doc, {}, at, leases={k: set(v) for k, v in lease_groups.items()}, trusts=trusts)
    return {(x["group"], x["anchor"]) for x in p["add"]}


# --- state: lock, last applied revision, logout queue, run log ------------------------------------------------------

class State:
    """Every file is written whole (a temporary file, then a rename). A file that does not read is set aside with a
    timestamp and treated as absent, and the run says so (state.recovered): absent is always the cautious reading (no
    history to compare with, but the broker's high-water mark still holds; no previous desired set, so the cap counts
    what the broker holds; an empty logout queue, refilled from the written-ahead removals)."""

    def __init__(self, path: Path, lease: timedelta):
        self.path, self.lease = path, lease
        path.mkdir(parents=True, exist_ok=True)
        self.recovered: list[str] = []

    def _read(self, name: str):
        f = self.path / name
        if not f.exists():
            return None
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            stamp = clock.now().strftime("%Y%m%dT%H%M%SZ")
            os.replace(f, self.path / f"{name}.corrupt-{stamp}")
            self.recovered.append(f"{name} did not read and was set aside")
            return None

    def _write(self, name: str, obj) -> None:
        tmp = self.path / f"{name}.tmp"
        with tmp.open("w", encoding="utf-8") as h:
            h.write(json.dumps(obj, default=str, sort_keys=True))
            h.flush()
            os.fsync(h.fileno())
        os.replace(tmp, self.path / name)

    def intent(self) -> list | None:
        v = self._read("removing.json")
        return v if isinstance(v, list) else None

    def save_intent(self, removals: list) -> None:
        """Written before any removal: if the run dies between a removal and its logout, the next run logs out
        everyone it meant to remove (a logout of someone still a member costs one sign-in)."""
        self._write("removing.json", [list(r) for r in removals])

    def clear_intent(self) -> None:
        (self.path / "removing.json").unlink(missing_ok=True)

    def lock(self) -> None:
        """One writer: the lock is owned by a random token, never by a process id (every container is
        pid 1); it is created exclusively, and an expired one is taken over by an atomic rename, so of two takers one
        wins. Only the owner renews or releases it."""
        import secrets
        f = self.path / "writer.lock"
        token = secrets.token_hex(16)
        for _ in range(2):
            try:
                fd = os.open(f, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if self._held(f).get("until", 0) > time.time():
                    raise Refused("another reconciler holds the writer lock") from None
                stale = self.path / f"writer.lock.stale.{token}"
                try:
                    os.rename(f, stale)            # one taker wins; the other finds the file gone and retries once
                except FileNotFoundError:
                    continue
                stale.unlink(missing_ok=True)
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as h:
                h.write(json.dumps({"token": token, "until": time.time() + self.lease.total_seconds()}))
            self.token = token
            return
        raise Refused("the writer lock changed hands while taking it over")

    @staticmethod
    def _held(f: Path) -> dict:
        try:
            held = json.loads(f.read_text(encoding="utf-8"))
            return held if isinstance(held, dict) else {}
        except (ValueError, OSError):
            return {}

    def renew(self) -> None:
        """Extend the lease, only while this run still owns the lock."""
        f = self.path / "writer.lock"
        if getattr(self, "token", None) is None or self._held(f).get("token") != self.token:
            raise Refused("the writer lock was lost during the run")
        tmp = self.path / f"writer.lock.{self.token}.tmp"
        tmp.write_text(json.dumps({"token": self.token, "until": time.time() + self.lease.total_seconds()}), encoding="utf-8")
        os.replace(tmp, f)

    def unlock(self) -> None:
        """Release the lock only when this run took it (a refused run never deletes another's lock)."""
        f = self.path / "writer.lock"
        if getattr(self, "token", None) is not None and self._held(f).get("token") == self.token:
            f.unlink(missing_ok=True)
        self.token = None

    def last_applied(self) -> dict | None:
        v = self._read("last-applied.json")
        return v if isinstance(v, dict) else None

    def save_applied(self, doc: dict) -> None:
        self._write("last-applied.json", doc)

    def history_version(self) -> int:
        """The records-key history version the last applied records came under (#41 F8); 1 before any rotation."""
        v = self._read("history-version.json")
        return int(v.get("version", 1)) if isinstance(v, dict) and isinstance(v.get("version"), int) else 1

    def save_history_version(self, version: int) -> None:
        self._write("history-version.json", {"version": int(version)})

    def logouts(self) -> dict:
        v = self._read("logout-queue.json")
        return v if isinstance(v, dict) else {}

    def save_logouts(self, q: dict) -> None:
        self._write("logout-queue.json", q)

    def override(self, plan_hash: str) -> bool:
        f = self.path / "override-removal-cap"
        return f.exists() and f.read_text(encoding="utf-8").strip() == plan_hash

    def log(self, run: dict, keep: int) -> None:
        f = self.path / "runs.jsonl"
        try:
            lines = f.read_text(encoding="utf-8").splitlines() if f.exists() else []
        except UnicodeDecodeError:
            lines = []
            self.recovered.append("runs.jsonl did not read and was started again")
        lines = (lines + [json.dumps(run, default=str)])[-keep:]
        tmp = self.path / "runs.jsonl.tmp"
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, f)

    def last_desired(self) -> set | None:
        v = self._read("desired.json")
        try:
            return {tuple(x) for x in v} if isinstance(v, list) else None
        except TypeError:
            self.recovered.append("desired.json held something other than pairs and was ignored")
            return None

    def save_desired(self, want: set) -> None:
        self._write("desired.json", sorted(want))

    def observed(self, have: set) -> None:
        self._write("observed.json", sorted(have))          # the desk reads it while this runs: never half a file

    def usernames(self, names: dict) -> None:
        """Anchor -> the broker's username, for edge leases (Warpgate and the facade know people by it)."""
        self._write("usernames.json", dict(sorted(names.items())))

    def identity_map(self, sealed: dict) -> None:
        """The sealed identity map (keyclerk.identity_map): what the signer checks a lease's username and e-mail against."""
        self._write("identity-map.json", sealed)

    def console_cursor(self, at: datetime) -> int:
        """The newest admin event time read for console grants (ms); a first run looks back a day."""
        v = self._read("console-grants.json")
        return int(v["since_ms"]) if isinstance(v, dict) and isinstance(v.get("since_ms"), int) else \
            int((at - timedelta(days=1)).timestamp() * 1000)

    def save_console_cursor(self, since_ms: int) -> None:
        self._write("console-grants.json", {"since_ms": since_ms})

    def emails(self, emails: dict) -> None:
        """Anchor -> the broker's verified e-mail, for edge leases (an edge gateway such as Warpgate matches an SSO login by it).
        Only verified addresses; the desk puts one only in leases on edges that person holds a lease on."""
        self._write("emails.json", dict(sorted(emails.items())))


def _history_errors(last: dict | None, new: dict) -> list[str]:
    if last is None:
        return []
    return records.guard(json.loads(json.dumps(last, default=str)), json.loads(json.dumps(new, default=str)))


# --- one run ------------------------------------------------------------------------------------------------------

MARK_FORMAT = "kc-mark-v1"


def recovery_base(store, seen: int, last: dict | None) -> tuple[dict | None, int, int | None, dict | None]:
    """(the last applied records still a base, the history version held, the revision at its switch when that
    version is newer than the one last applied under, what was reset) (#41 F8, TUF's fast-forward attack): after a
    recovery the records a stolen key signed past the switch are no base, and the high-water mark counts only to the
    switch. A planned rotation's switch lies past everything applied, so nothing changes then."""
    from keyclerk.store import replay
    hv = 1 if isinstance(store.pinned, str) else store.pinned.version
    if hv <= seen:
        return last, hv, None, None
    back = replay.revision_at(store, store.pinned.switch)
    if back is not None and last and isinstance(last.get("revision"), int) and last["revision"] > back:
        return None, hv, back, {"history": hv, "switch": store.pinned.switch, "revision": back,
                                "dropped_applied": last["revision"]}
    return last, hv, back, None


def _remove_intruders_only(args, state, target, run: dict, problem: str, mark, rev) -> None:
    """The revision is refused, but memberships the records never required are still taken out of managed groups:
    otherwise whoever can write the mark could freeze every removal (review 2026-10-26 E4). They are judged against
    the last desired set the reconciler accepted; with none, only members without an anchor go."""
    run["incident"] = {"kind": "high-water-mark", "why": problem, "mark": mark, "records_revision": rev}
    run["alert"] = ("the records revision was refused against the broker's high-water mark; intruders are still removed:"
                    " see incident")
    before = state.last_desired()
    have = target.read_full()
    want = set(before) if before is not None else {r for r in have if not str(r[1]).startswith("uid:")}
    plan = {**target.plan(want, have), "add": []}
    run.update({"observed_before": len(have), "add": [], "remove": plan["remove"],
                "intrusions_removed": len(plan["remove"]), "findings": plan["findings"] + target.findings})
    if args.apply and plan["remove"]:
        state.renew()
        state.save_intent(plan["remove"])
        key = hashlib.sha256((run.get("records_sha256", "") + json.dumps(
            {"add": [], "remove": sorted(map(list, plan["remove"]))})).encode()).hexdigest()
        res = target.apply(plan, key=key, dry_run=False)
        run.update({"failed": res.get("failed", []), "missing_people": res.get("missing_people", [])})
        state.clear_intent()
UNSIGNED = "the broker's high-water mark is unsigned"


MARK_FORMAT_V2 = "kc-mark-v2"                 # #41 F8: the mark names the records-key history version it holds under


def _mark_bytes(realm: str, revision: int, history: int | None = None) -> bytes:
    if history is None:
        return f"{MARK_FORMAT}|{realm}|{revision}".encode()
    return f"{MARK_FORMAT_V2}|{realm}|{revision}|{history}".encode()


def mark_key(args):
    """The reconciler's own key for the high-water mark (review 2026-10-26 E4): a file with an Ed25519 private key,
    64 hex digits, kept with the reconciler and nowhere else."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = getattr(args, "mark_key", None)
    if not path:
        return None
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(path), 200).strip()))
    except (OSError, ValueError):
        raise Refused(f"--mark-key {path}: not a readable Ed25519 private key (64 hex digits)") from None


def sign_mark(key, realm: str, revision: int, history: int | None = None) -> str:
    """kc-mark-v1 for a log never rotated; kc-mark-v2 with the history version after a rotation (#41 F8)."""
    if history is None or history <= 1:
        return f"{MARK_FORMAT}:{revision}:{key.sign(_mark_bytes(realm, revision)).hex()}"
    return f"{MARK_FORMAT_V2}:{revision}:{history}:{key.sign(_mark_bytes(realm, revision, history)).hex()}"


def mark_history(raw) -> int:
    """The history version a mark names: 1 for kc-mark-v1 (and anything unsigned)."""
    parts = str(raw or "").split(":")
    return int(parts[2]) if len(parts) == 4 and parts[0] == MARK_FORMAT_V2 and parts[2].isdigit() else 1


def read_mark(raw, key, realm: str) -> tuple[int | None, str | None]:
    """(the revision the mark names, the problem with it); (None, None) before the first applied revision."""
    if raw is None:
        return None, None
    parts = str(raw).split(":")
    if len(parts) == 3 and parts[0] == MARK_FORMAT and parts[1].isdigit() and len(parts[1]) <= 18:
        revision = int(parts[1])
        try:
            key.public_key().verify(bytes.fromhex(parts[2]), _mark_bytes(realm, revision))
            return revision, None
        except Exception:   # noqa: BLE001 - malformed or by another key: not this reconciler's mark
            return revision, "the broker's high-water mark does not verify with this reconciler's key"
    if len(parts) == 4 and parts[0] == MARK_FORMAT_V2 and parts[1].isdigit() and len(parts[1]) <= 18 \
            and parts[2].isdigit() and len(parts[2]) <= 9:
        revision, history = int(parts[1]), int(parts[2])
        try:
            key.public_key().verify(bytes.fromhex(parts[3]), _mark_bytes(realm, revision, history))
            return revision, None
        except Exception:   # noqa: BLE001 - malformed or by another key: not this reconciler's mark
            return revision, "the broker's high-water mark does not verify with this reconciler's key"
    if str(raw).isdigit() and len(str(raw)) <= 18:
        return int(raw), UNSIGNED
    return None, "the broker's high-water mark does not read"


def run_once(args, at: datetime | None = None, target: KeycloakTarget | None = None, proofs=None) -> dict:
    at = at or clock.now()
    started = time.time()
    cfg = config.current()
    lim = cfg["reconcile"]
    run = {"at": at.isoformat(), "realm": args.realm, "applied": False, "config_sha256": args.config_hash}
    state, log_ids = None, None
    try:
        state = State(Path(args.state), timedelta(seconds=max(60, 3 * args.interval)))
        state.lock()
        if target is None:
            writer = token(args.keycloak, args.realm, args.client, _secret(args.secret_file))
            reader = token(args.keycloak, args.realm, args.reader_client, _secret(args.reader_secret_file)) \
                if args.reader_client else writer
            target = KeycloakTarget(keycloak=args.keycloak, realm=args.realm, token=writer, admin_token=writer,
                                    reader_token=reader, marker=lim["managed_marker"],
                                    logout_on_removal=lim.get("logout_on_removal", True),
                                    privileged_roles=tuple(lim.get("privileged_roles", ())))
        if getattr(args, "log_replica", None):          # decision 0022 S5: the records are the signed change log
            doc, head, target, log_ids = _from_log(args, target)
            run["records_sha256"] = head                  # the head names this state as the hash names a revision
        _finish_removals(state, target, at)
        if hasattr(target, "console_grants"):          # decision 0030 point 3: grants made around KeyClerk, report-only
            found, newest, why = target.console_grants(state.console_cursor(at))
            run["console_grants"] = found
            if why:
                run["console_grants_unread"] = why
            state.save_console_cursor(newest)
        if log_ids is None:
            if Path(args.records).is_dir():
                raise Refused("records must be one file: a directory cannot be signed or read atomically")
            raw = guard.read_bounded(Path(args.records)).encode("utf-8")   # read once; only these bytes are used
            run["records_sha256"] = hashlib.sha256(raw).hexdigest()
            if args.signing_key:
                verify_signature(raw, Path(args.records + ".sig"), Path(args.signing_key))
            elif not args.allow_unsigned:
                raise Refused("unsigned records: pass --signing-key, or --allow-unsigned for a local demo")
            doc = records.loads(raw.decode("utf-8"))
        policy = cfg.get("approvals") or {}
        if policy.get("proofs") == "required":                # every approval the approver's own (decision 0006)
            from keyclerk import approvals
            if proofs is None:
                if not getattr(args, "approval_issuer", None) or not getattr(args, "approval_audience", None):
                    raise Refused("approvals need proofs: pass --approval-issuer and --approval-audience")
                proofs = approvals.BrokerProofs(args.approval_issuer, args.approval_audience,
                                                policy.get("max_age_seconds", 300),
                                                f"{args.keycloak}/realms/{args.realm}/protocol/openid-connect/certs",
                                                Path(args.state) / "broker-keys.json", acr=policy.get("acr"))
            if log_ids is not None:                       # proofs name internal anchors on the log (decision 0028)
                from keyclerk import anchors
                proofs.resolve = lambda claims: anchors.resolve(log_ids["store"], claims)
            unproven = approvals.check(doc, proofs, policy)
            if unproven:
                raise Refused(f"{len(unproven)} approvals without a valid proof: {guard.safe_for_log(unproven[0], 200)}"
                              + ("" if (policy.get("accepted_without_proof")) else f"; {approvals.PIN_HINT}"))
        errs = check_records(doc, log_backed=log_ids is not None)
        if errs:
            raise Refused(f"records refused by {len(errs)} checks: {guard.safe_for_log(errs[0], 200)}")
        last, hv, back = state.last_applied(), 1, None
        if log_ids is not None:                           # #41 F8: a recovery resets what a stolen key pushed forward
            last, hv, back, rec = recovery_base(log_ids["store"], state.history_version(), last)
            if rec:
                run["recovery"] = rec
        hist = _history_errors(last, doc)
        if hist:
            raise Refused(f"records rewrite history: {guard.safe_for_log(hist[0], 200)}")
        # the serial is signed with the records; the newest applied is kept in the broker too, so a lost or wiped
        # state folder cannot let an older signed revision replay
        rev = doc.get("revision")
        keeps_mark = hasattr(target, "high_water")
        mkey = mark_key(args) if keeps_mark else None
        if keeps_mark and mkey is None:
            raise Refused("the reconciler signs the broker's high-water mark: pass --mark-key, a file with an Ed25519 "
                          "private key (64 hex digits) that only the reconciler reads")
        raw_mark = target.high_water() if keeps_mark else None
        mark, problem = read_mark(raw_mark, mkey, args.realm) if keeps_mark else (None, None)
        if back is not None and not problem and isinstance(mark, int) and mark > back and mark_history(raw_mark) < hv:
            run.setdefault("recovery", {"history": hv, "revision": back})["mark_was"] = mark
            mark = back                                   # F8: the mark under the older history counts to the switch
            run["incident"] = {"kind": "records_key_recovery", "why": f"the records key was recovered (history "
                               f"version {hv}): the high-water mark goes back to revision {back}, the switch"}
        resign = problem == UNSIGNED
        if resign and getattr(args, "adopt_mark", False) and isinstance(rev, int) and mark <= rev:
            problem = None                               # an upgrade: the unsigned mark is signed at this run's apply
        floor = max([x for x in (mark, (last or {}).get("revision")) if isinstance(x, int)], default=None)
        if not problem and floor is not None and not (isinstance(rev, int) and rev >= floor):
            problem = f"records revision {rev} is older than revision {floor} already applied: never replayed"
        if problem:                                      # the revision waits; what the records never required still goes
            _remove_intruders_only(args, state, target, run, problem, mark, rev)
            raise Refused(problem)
        run["revision"] = rev
        trusts = load_trusts(args.trust)
        want = desired(doc, at, trusts)
        have = target.read_full()
        plan = target.plan(want, have)
        run.update({"desired": len(want), "observed_before": len(have), "add": plan["add"], "remove": plan["remove"],
                    "findings": plan["findings"] + target.findings})
        # The cap guards against a records revision that takes away much at once: it counts removals of what the
        # records required before. Memberships the records never required (added in the broker by hand, members
        # without an anchor) are intrusions: always removed, so they cannot be used to block the run.
        before = state.last_desired()
        # with no earlier desired set (a first run, a lost or set-aside state) nothing tells an intrusion from a lawful
        # holder, so every anchored member counts against the cap; only members without an anchor always go
        lawful = [r for r in plan["remove"]
                  if (tuple(r) in before if before is not None else not str(r[1]).startswith("uid:"))]
        intruders = [r for r in plan["remove"] if r not in lawful]
        run["intrusions_removed"] = len(intruders)
        # the override names the lawful plan: the revision, what it adds and what it takes away
        plan_hash = hashlib.sha256((run["records_sha256"] + json.dumps(
            {"add": sorted(map(list, plan["add"])), "remove": sorted(map(list, lawful))}, sort_keys=True)).encode()).hexdigest()
        run["plan_sha256"] = plan_hash
        if intruders:
            run["alert"] = f"{len(intruders)} memberships the records never required were in managed groups"
            if hasattr(target, "who_added"):           # who did it, from the broker's admin events (a finding only)
                for g, a in intruders:
                    by = target.who_added(g, a)
                    if by:
                        run["findings"].append({"group": g, "anchor": a, "why": "added by hand in the broker", **by})
        cap = min(lim["max_removals_per_run"], max(1, int(lim["max_removal_share"] * max(len(before or have), 1))))
        if len(lawful) > cap and not state.override(plan_hash):
            plan = {**plan, "add": [], "remove": intruders}      # intrusions still go; the revision waits
            run["refused"] = (f"{len(lawful)} removals exceed the cap of {cap}: write the plan hash to "
                              f"override-removal-cap to allow exactly this plan")
        if args.apply:
            state.renew()
            if plan["remove"]:
                state.save_intent(plan["remove"])
            key = hashlib.sha256((run["records_sha256"] + json.dumps(
                {"add": sorted(map(list, plan["add"])), "remove": sorted(map(list, plan["remove"]))})).encode()).hexdigest()
            res = target.apply(plan, key=key, dry_run=False)           # idempotency: the plan actually applied
            run["applied"] = not run.get("refused")
            run.update({"failed": res.get("failed", []), "missing_people": res.get("missing_people", [])})
            queue = state.logouts()
            for uid in res.get("logout_pending", []):
                queue.setdefault(uid, at.isoformat())
            state.save_logouts(queue)
            state.clear_intent()
            if not run.get("refused"):
                state.save_applied(doc)
                state.save_desired(want)
                if log_ids is not None:
                    state.save_history_version(hv)
                if isinstance(rev, int) and (rev != mark or resign or mark_history(raw_mark) < hv) \
                        and hasattr(target, "set_high_water"):
                    target.set_high_water(sign_mark(mkey, args.realm, rev, hv))
        state.observed(target.read_full() if args.apply else have)
        if log_ids is not None and args.apply:            # phase 2: people seen through their attribute get linked
            run["findings"] = run.get("findings", []) + target.link_subjects(log_ids["signer"], want)   # never on a dry run
        names, mails = getattr(target, "usernames", {}) or {}, getattr(target, "emails", {}) or {}
        state.usernames(names)
        state.emails(mails)
        if mkey is not None:                          # sealed with the mark's key, for the checking signer (0021 point 2)
            from keyclerk import identity_map
            state.identity_map(identity_map.seal(mkey, args.realm, (state.last_applied() or {}).get("revision"), at,
                                                 names, mails))
    except (Refused, guard.InputRejected, LogRefused) as e:
        run["refused"] = guard.safe_for_log(e)
    except Exception as e:   # noqa: BLE001 - recorded, retried next run, never widens anything
        run["error"] = f"{type(e).__name__}: {guard.safe_for_log(e, 200)}"
    finally:
        if state is not None and state.recovered:
            run["recovered"] = state.recovered
            run["alert"] = run.get("alert") or "the reconciler's state was damaged and set aside: see recovered"
        if state is not None and args.apply and target is not None:
            _retry_logouts(state, target, run, at, lim)     # whatever else happened: removed people lose their sessions
        if log_ids is not None:
            log_ids["source"].close()
        run["seconds"] = round(time.time() - started, 3)
        if state is not None:
            try:
                state.log(run, lim["keep_runs"])
            except OSError as e:   # the run is still reported on stdout and fails; it never passes silently
                run["error"] = run.get("error") or f"run log not written: {type(e).__name__}"
            try:
                state.unlock()
            except OSError:
                pass
    return run


def _from_log(args, target):
    """(records, head, the translating target, its context) from the reconciler's replica of the change log."""
    from keyclerk.signer import SignerClient
    from keyclerk.store.log_reconcile import Identities, LogRecords, LogTarget
    signer = getattr(args, "signer_client", None) or SignerClient(args.signer, args.signer_token)
    pinned = guard.read_bounded(Path(args.records_key), 200).strip()
    src = LogRecords(Path(args.log_replica), signer, pinned, args.realm)
    try:
        doc, head, _ = src.read()
        ids = Identities(doc, src.store)
    except Exception:
        src.close()
        raise
    return doc, head, LogTarget(target, ids), {"store": src.store, "signer": signer, "source": src}


def _finish_removals(state: State, target, at: datetime) -> None:
    """A run that died after writing its removals ahead: queue a logout for each person it meant to remove."""
    intent = state.intent()
    if not intent:
        return
    if target is None or not hasattr(target, "user"):
        state.recovered.append(f"{len(intent)} removals of an interrupted run could not be resolved yet")
        return
    queue = state.logouts()
    for _, anchor in intent:
        try:
            u = {"id": anchor[4:]} if str(anchor).startswith("uid:") else target.user(anchor)
        except Exception:   # noqa: BLE001 - kept for the next run
            return
        if u and u.get("id"):
            queue.setdefault(u["id"], at.isoformat())
    state.save_logouts(queue)
    state.clear_intent()
    state.recovered.append(f"an interrupted run's {len(intent)} removals: their people are logged out")


def _retry_logouts(state: State, target, run: dict, at: datetime, lim: dict) -> None:
    try:
        queue = state.logouts()
        for uid in list(queue):
            try:
                target.logout(uid)
                queue.pop(uid)
            except Exception:   # noqa: BLE001 - stays queued
                pass
        state.save_logouts(queue)
    except OSError as e:
        run["error"] = run.get("error") or f"logout queue not kept: {type(e).__name__}"
        return
    oldest = min((guard.timestamp(t) for t in queue.values()), default=None)
    run["logout_queue"] = len(queue)
    if oldest and at - oldest > timedelta(minutes=lim["logout_retry_minutes"]):
        run["alert"] = f"{len(queue)} logouts pending since {oldest.isoformat()}"


def parse(argv: list[str]):
    ap = argparse.ArgumentParser(prog="keyclerk.reconcile")
    ap.add_argument("--config", required=True)
    ap.add_argument("--records", help="the signed records file (the YAML store); or --log-replica")
    ap.add_argument("--keycloak", required=True)
    ap.add_argument("--realm", required=True)
    ap.add_argument("--client", default="keyclerk-reconciler")
    ap.add_argument("--secret-file", required=True)
    ap.add_argument("--reader-client")
    ap.add_argument("--reader-secret-file")
    ap.add_argument("--state", required=True)
    ap.add_argument("--signing-key")
    ap.add_argument("--allow-unsigned", action="store_true")
    ap.add_argument("--trust")
    ap.add_argument("--approval-issuer", action="append", default=[],
                    help="the broker issuer whose ID tokens prove approvals (as the browser reached it)")
    ap.add_argument("--approval-audience", action="append", default=[], help="a client whose ID tokens count as proofs")
    ap.add_argument("--log-replica", help="the reconciler's replica of the change log (decision 0022): records from the "
                                         "log, followed from --signer, instead of --records")
    ap.add_argument("--signer", help="with --log-replica: the checking signer, unix:/path or tcp:127.0.0.1:port")
    ap.add_argument("--signer-token", help="with a TCP signer: the token file")
    ap.add_argument("--records-key", help="with --log-replica: the records public key (hex), pinned here")
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--apply", action="store_true", help="write to the broker; without it a run is a dry run")
    ap.add_argument("--mark-key", help="the reconciler's Ed25519 private key file (64 hex digits) for the broker's "
                                       "high-water mark; required with a broker that keeps one")
    ap.add_argument("--adopt-mark", action="store_true",
                    help="once, on upgrade: sign an unsigned high-water mark that is not ahead of the records")
    a = ap.parse_args(argv)
    guard.broker_url(a.keycloak)
    guard.name(a.realm, "realm")
    guard.name(a.client, "client")
    if a.reader_client:
        guard.name(a.reader_client, "reader client")
        if not a.reader_secret_file:
            ap.error("--reader-client needs --reader-secret-file")
    if bool(a.records) == bool(a.log_replica):
        ap.error("one of --records (the YAML store) or --log-replica (the change log)")
    if a.log_replica and not (a.signer and a.records_key):
        ap.error("--log-replica needs --signer and --records-key")
    if not 10 <= a.interval <= 86400:
        ap.error("--interval must be between 10 and 86400 seconds")
    return a


def main(argv: list[str]) -> int:
    args = parse(argv)
    raw = guard.read_bounded(Path(args.config))
    args.config_hash = hashlib.sha256(raw.encode()).hexdigest()
    config.configure(args.config)
    while True:
        run = run_once(args)
        print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in run.items()}), flush=True)
        if args.once:
            return 1 if run.get("refused") or run.get("error") else 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
