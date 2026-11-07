# SPDX-License-Identifier: EUPL-1.2
"""The bundle key in the checking signer (0021 point 1): the signer builds every edge bundle itself, from its own
replica of the change log, and seals it with a key the desk never holds.

What the desk supplies is only what the signer checks or what the edge pins anyway:
- the serial it would like, raised above the signer's own floor for the edge when it is not: never back;
- the officer's sealed ceiling, verified here under the officer key the records hold now;
- the policy references, which an edge verifies against the release manifest it pins;
- the first time a derived lease was issued, accepted only when it is not in the future;
- the reconciler's sealed identity map (0021 point 2), verified under the pinned reconciler key, never older than the
  last one accepted: the usernames in a bundle come from it, never from the desk;
- the edge's TPM quote and signed request, which the signer verifies itself (0.29 review S12);
- evidence entries and escrow halves, which the signer checks and keeps (their head, digest and custodians) before it
  acknowledges anything, and custodians' fresh sign-ins, which it counts (0.29 review S2).

So a taken-over desk can refuse, delay or drop leases, never add one: every lease, visit lease and revocation in a
sealed bundle is one the records hold.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ATTESTED = ("basic", "assured")
ESCROW_ACK, ESCROW_STATUS, EVIDENCE_ACK = "kc-edge-escrow-ack-v1", "kc-edge-escrow-status-v1", "kc-edge-evidence-ack-v1"
EVIDENCE_FIELDS = {"seq", "prev", "sha256", "size", "session", "at"}
EVIDENCE_BATCH = 500
ESCROW_ITEMS = 500                               # per edge; past it the oldest item both custodians confirmed goes
IDENTITY_MAX_HOURS = 24                          # default age past which the identity map vouches for nobody (S7)
PROOF_MINUTES = 10                               # a sign-in that signs an unlock or a confirmation is this fresh (S5)


def _proof_fresh(claims, now) -> None:
    """A proof the signer acts on now was issued within PROOF_MINUTES of its clock (0.29 review S5): an approval's
    proof is checked again years later, an unlock's or a confirmation's only once, now."""
    from datetime import timedelta

    from keyclerk import edge as E
    iat = claims.get("iat") if isinstance(claims, dict) else None
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise EdgeRefused("the sign-in carries no issue time: sign in again")
    t = now.timestamp()
    if iat > t + E.SKEW or t - iat > timedelta(minutes=PROOF_MINUTES).total_seconds():
        raise EdgeRefused(f"the sign-in is not from the last {PROOF_MINUTES} minutes by the signer's clock: sign in again")


class ReplicaSource:
    """The change log the signer keeps (decision 0022): records replayed, the head an edge echoes."""

    def __init__(self, store):
        self.store, self.realm = store, store.realm
        self._doc: tuple[int, dict] | None = None

    def records(self) -> dict:
        from keyclerk.store import replay
        size = self.store.size()
        if self._doc is None or self._doc[0] != size:
            self._doc = (size, replay.records(self.store))
        return self._doc[1]

    def head(self) -> dict:
        from keyclerk.store import replay
        h = self.store.head()
        return {"revision": replay.revision(self.store) or 0, "size": self.store.size(),
                "head": h.hex() if h else "0" * 64}


class SignedYamlSource:
    """The YAML records the signer last signed (decision 0015), read through the signer's own check of their hash."""

    def __init__(self, last):
        self.last = last                                 # Signer._last: (revision, sha256, raw)
        self._doc: tuple[str, dict] | None = None

    def records(self) -> dict:
        from keyclerk import records
        _, sha, raw = self.last()
        if self._doc is None or self._doc[0] != sha:
            self._doc = (sha, records.loads(raw))
        return self._doc[1]

    @property
    def realm(self) -> str:
        return self.records().get("realm")

    def head(self) -> dict:
        rev, sha, _ = self.last()
        return {"revision": rev, "head": sha or "0" * 64}


class EdgeRefused(Exception):
    pass


class EdgeSealer:
    def __init__(self, state: Path, source, clock=None):
        self.dir = Path(state) / "edge"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.source = source
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.identity_key: str | None = None
        self.ha = False                                  # set by the signer: HA nodes share one imported key
        self._map = None                                 # (pinned key, the identity map it opened)
        self.lock = threading.Lock()
        self.record = None                               # D3: the signer's record_own, where there is a change log
        self._key_lock = threading.Lock()                # the key is read inside self.lock: its own lock (S9)
        self._key = None

    # --- keys -----------------------------------------------------------------------------------------------------
    @property
    def key(self):
        """The bundle key: made only while the signer's records name no edge and it has sealed nothing; once an edge
        may have pinned it, a missing key is an import or a restore, never a new key (edges would refuse every bundle;
        found by the edge implementation for an upgrade whose desk copy was deleted, not imported). In HA mode never made at all: every node
        must seal with the one key the edges pin, so it is imported into each (import-bundle-key)."""
        from keyclerk import edge as E
        with self._key_lock:
            return self._key_locked(E)

    def _key_locked(self, E):
        if self._key is None:
            f = self.dir / "bundle.key"
            if self.ha and not f.exists():
                raise EdgeRefused("in HA mode the nodes share one bundle key: import the same file into every node "
                                  "(python -m keyclerk.init bundle-key --out FILE, then python -m keyclerk.signer "
                                  "import-bundle-key --state DIR --from FILE on each)")
            if not f.exists() and (self._serials() or self._records().get("edges")):
                raise EdgeRefused("the signer holds no bundle key, and its records name enrolled edges: a new key would "
                                  "cut every one of them off. Import the key they pinned (python -m keyclerk.signer "
                                  "import-bundle-key --state DIR --from FILE); for a new deployment whose first edge "
                                  "was enrolled before its key was read, make one with python -m keyclerk.init "
                                  "bundle-key --out FILE and import it")
            self._key = E.load_or_make_key(f, allow_create=True)
        return self._key

    def rollover_begin(self, next_from: Path | None = None) -> list[dict]:
        """Start a bundle-key rollover (#41, F6): a next key (bundle-next.key, made in the signer or, for HA nodes that
        share one bundle key, the same file imported into each node with next_from) and, for every live edge, a
        kc-edge-key-rollover-v2 signed by the current key, for the edge's officer to co-sign (edge_cli cosign).
        Nothing changes for the edges until rollover_finish."""
        from datetime import datetime, timezone

        from keyclerk import delegation as D
        from keyclerk import edge as E
        with self.lock:
            old = E.public_hex(self.key)
            nxt = self.dir / "bundle-next.key"
            if next_from is not None:                    # HA: every node begins from the same next key
                theirs = E.public_hex(E.load_or_make_key(Path(next_from), allow_create=False))
                if nxt.exists() and E.public_hex(E.load_or_make_key(nxt, allow_create=False)) != theirs:
                    raise EdgeRefused("this node already began a rollover to another next key: finish or remove it "
                                      "(bundle-next.key) first")
                if not nxt.exists():
                    data = Path(next_from).read_bytes()
                    fd = os.open(nxt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as h:
                        h.write(data)
                        h.flush()
                        os.fsync(h.fileno())
            elif self.ha and not nxt.exists():
                raise EdgeRefused("in HA mode the nodes share one bundle key: make the next key once (python -m "
                                  "keyclerk.init bundle-key --out NEXT) and begin on every node with --next NEXT")
            new = E.public_hex(E.load_or_make_key(nxt, allow_create=True))
            if new == old:
                raise EdgeRefused("the next key is the current one")
            now = self.clock() if self.clock else datetime.now(timezone.utc)
            doc = self._records()
            live = [e["edge_id"] for e in doc.get("edges", []) if not D._revs(doc, e["edge_id"], now)]
            return [E.cosign(self.key, E.rollover_statement(eid, old, new, E._iso(now)), E.ROLLOVER_FORMAT_V2)
                    for eid in live]

    def rollover_finish(self, statements: list) -> dict:
        """Move to the next key once every live edge's statement carries its officer's signature (the officer key in
        the signer's own records) as well as the current key's; the statements are kept for the desk to serve each edge
        its own (GET /edge-key?edge=ID). The old key is kept as bundle-retired-<n>.key until the operator destroys it."""
        from keyclerk import delegation as D
        from keyclerk import edge as E
        from keyclerk import edge_records
        with self.lock:
            nxt = self.dir / "bundle-next.key"
            if not nxt.exists():
                raise EdgeRefused("no rollover was begun (rollover_begin)")
            old, new = E.public_hex(self.key), E.public_hex(E.load_or_make_key(nxt, allow_create=False))
            now = self.clock()
            doc = self._records()
            got = {}
            for st in statements or []:
                body = E._parse(E._raw(st["bytes"]))
                got[body.get("edge")] = st
            out = {}
            for e in doc.get("edges", []):
                if D._revs(doc, e["edge_id"], now):
                    continue
                st = got.get(e["edge_id"])
                if st is None:
                    raise EdgeRefused(f"no co-signed rollover for edge {e['edge_id']}: every live edge moves together")
                officer = edge_records.current(doc, e, now)["officer_key"]
                try:
                    E.accept_rollover(st, {"edge": e["edge_id"], "bundle_key": old, "officer_key": officer})
                except ValueError as x:
                    raise EdgeRefused(f"the rollover for edge {e['edge_id']} does not hold: {x}") from None
                if E._parse(E._raw(st["bytes"]))["new_key"] != new:
                    raise EdgeRefused(f"the rollover for edge {e['edge_id']} names another key than the next one")
                out[e["edge_id"]] = st
            self._write("rollovers.json", out)
            n = len(list(self.dir.glob("bundle-retired-*.key"))) + 1
            os.replace(self.dir / "bundle.key", self.dir / f"bundle-retired-{n}.key")
            os.replace(nxt, self.dir / "bundle.key")
            self._key = None
            return {"old": old, "new": new, "edges": sorted(out)}

    def rollover_for(self, edge_id: str):
        """The kept rollover statement for one edge, or None."""
        return self._read("rollovers.json").get(edge_id)

    def public(self) -> dict:
        from keyclerk import edge as E
        pub = E.public_hex(self.key)
        return {"key": pub, "key_id": E.key_id(pub), "format": E.BUNDLE_FORMAT,
                "unlock_key": E.unlock_public(self.unlock_private), "unlock_format": E.UNLOCK_CONTEXT}

    @property
    def unlock_private(self):
        """The P-256 key behind phoned unlock codes (kc-unlock-v2): under the same rules as the bundle key, made only
        while the records name no edge and never in HA mode; otherwise imported (import-bundle-key --unlock-from)."""
        from keyclerk import edge as E
        if getattr(self, "_unlock", None) is None:
            f = self.dir / "unlock-v2.key"
            if not f.exists():
                if self.ha or self._serials() or self._records().get("edges"):
                    raise EdgeRefused("the signer holds no unlock key, and edges may have pinned one: import the desk's "
                                      "unlock-v2.key (python -m keyclerk.signer import-bundle-key --state DIR --from "
                                      "BUNDLE_KEY --unlock-from UNLOCK_KEY)")
                fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as h:
                    h.write(E.new_unlock_private())
                    h.flush()
                    os.fsync(h.fileno())
            self._unlock = E.unlock_private(f.read_text(encoding="utf-8").strip())
        return self._unlock

    def import_unlock_key(self, path: Path) -> None:
        """Move a desk's unlock-v2.key (a P-256 scalar in hex) into the signer once; another key already held is refused."""
        from keyclerk import edge as E
        own = self.dir / "unlock-v2.key"
        theirs = Path(path).read_text(encoding="utf-8").strip()
        E.unlock_private(theirs)                         # a valid key, or ValueError
        if own.exists():
            if own.read_text(encoding="utf-8").strip() != theirs:
                raise EdgeRefused("the signer already holds another unlock key: edges pinned one of the two")
            return
        fd = os.open(own, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            h.write(theirs)
            h.flush()
            os.fsync(h.fileno())
        self._unlock = None

    def import_key(self, path: Path) -> dict:
        """Move a desk's bundle.key into the signer once (0.29.0 upgrade): enrolled edges keep the key they pinned.
        Refused when the signer already holds another key."""
        from keyclerk import edge as E
        own = self.dir / "bundle.key"
        theirs = E.load_or_make_key(Path(path), allow_create=False)
        if own.exists():
            if E.public_hex(E.load_or_make_key(own, allow_create=False)) != E.public_hex(theirs):
                raise EdgeRefused("the signer already holds another bundle key: edges pinned one of the two; restore the "
                                  "one they pinned, never both")
        else:
            data = Path(path).read_bytes()
            fd = os.open(own, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as h:
                h.write(data)
                h.flush()
                os.fsync(h.fileno())
        self._key = None
        pub = E.public_hex(self.key)                  # the bundle key only: an import has no records to judge by
        return {"key": pub, "key_id": E.key_id(pub), "format": E.BUNDLE_FORMAT}

    # --- state ----------------------------------------------------------------------------------------------------
    def _read(self, name: str) -> dict:
        f = self.dir / name
        try:
            v = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
        except (OSError, ValueError):
            raise EdgeRefused(f"the signer's {name} does not read: restore the signer's state from a backup") from None
        return v if isinstance(v, dict) else {}

    def _write(self, name: str, obj: dict) -> None:
        f = self.dir / name
        tmp = f.with_suffix(f.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as h:
            h.write(json.dumps(obj, sort_keys=True))
            h.flush()
            os.fsync(h.fileno())
        os.replace(tmp, f)

    def _serials(self) -> dict:
        return self._read("serials.json")

    def _records(self) -> dict:
        return self.source.records()

    def _head(self) -> dict:
        return self.source.head()

    # --- the identity map -----------------------------------------------------------------------------------------
    def identity(self, sealed=None) -> dict | None:
        """The identity map the signer holds (0021 point 2). A map given is checked (the pinned reconciler key, this
        realm, never older than the one held) and kept; without one the kept map is used, verified again under the key
        pinned now. None only when this deployment has neither a pinned key nor a map: then no lease names a bastion
        account, so no bastion acts for anyone. A map without a pinned key, or a pinned key with no map yet, is
        refused: a desk cannot choose to drop the check.

        Its time is bounded both ways (0.29 review S7): a map more than five minutes ahead of the signer's clock is
        refused (it would refuse every later map), a kept one that far ahead is no floor, and a map older than
        edges.identity_map_max_hours (default 24) vouches for nobody until the reconciler's next map arrives."""
        from datetime import timedelta

        from keyclerk import edge as E
        from keyclerk import identity_map as M
        kept = self.dir / "identity-map.json"
        if sealed is None and not kept.exists():
            if not self.identity_key:
                return None
            raise EdgeRefused("the signer holds no identity map yet: the desk passes the reconciler's identity-map.json "
                              "when it changes (the reconciler writes it at every run with --mark-key)")
        if not self.identity_key:
            raise EdgeRefused("the signer has no reconciler key pinned for the identity map (--identity-key): it cannot "
                              "vouch for the bastion account a lease names")
        now = self.clock()
        if sealed is None:
            if self._map is not None and self._map[0] == self.identity_key:
                return self._fresh(self._map[1], now)
            sealed, seen = self._read("identity-map.json"), None
        else:
            seen = self._read("identity.json").get("at")
            if seen is not None and E._ts(seen) > now + timedelta(seconds=E.SKEW):
                seen = None                              # a map from the future is no floor (S7)
        try:
            m = M.open_map(sealed, self.identity_key, self.source.realm, not_before=seen)
        except ValueError as e:
            raise EdgeRefused(f"the identity map is refused: {e}") from None
        if E._ts(m["at"]) > now + timedelta(seconds=E.SKEW):
            raise EdgeRefused(f"the identity map is refused: it is from {m['at']}, more than five minutes ahead of the "
                              "signer's clock. Set the reconciler's clock right; its next run writes a map that holds")
        self._fresh(m, now)
        if seen is not None or not kept.exists():
            self._write("identity-map.json", sealed)
            self._write("identity.json", {"at": m["at"], "revision": m.get("revision")})
        self._map = (self.identity_key, m)
        return m

    @staticmethod
    def _fresh(m: dict, now) -> dict:
        from datetime import timedelta

        from keyclerk import config
        from keyclerk import edge as E
        hours = int((config.current().get("edges") or {}).get("identity_map_max_hours") or IDENTITY_MAX_HOURS)
        if E._ts(m["at"]) < now - timedelta(hours=hours):
            raise EdgeRefused(f"the identity map is from {m['at']}, older than {hours} hours (edges."
                              "identity_map_max_hours): it vouches for no bastion account now. The reconciler has not "
                              "run, or its identity-map.json does not reach the desk; run it with --mark-key")
        return m

    def accept_identity(self, sealed) -> dict:
        m = self.identity(sealed)
        return {"at": m["at"], "revision": m.get("revision"), "people": len(m["people"])}

    def names(self, sealed) -> dict:
        from keyclerk import identity_map as M
        m = self.identity(sealed)
        return M.usernames(m) if m else {}

    # --- the bundle -----------------------------------------------------------------------------------------------
    QUOTE_FRESH_SECONDS = 300
    CHALLENGE_MINUTES = 10

    def attest_challenge(self, edge_id: str) -> dict:
        """Credential activation, step one, in the signer (0.29 D3; decision 0016): the EK checked (the officer's pin,
        the manufacturer roots), a challenge encrypted to it bound to the AK's name; the secret's hash kept here."""
        import base64
        import hashlib
        import secrets

        from cryptography.hazmat.primitives import serialization

        from keyclerk import attest as A
        from keyclerk import config
        from keyclerk import edge as E
        from keyclerk import edge_records
        with self.lock:
            now = self.clock()
            doc = self._records()
            e = edge_records.current(doc, self._edge(doc, edge_id, now), now)
            t = e.get("tpm")
            if not t:
                raise EdgeRefused("this edge was enrolled without a TPM: it is a basic edge (decision 0016)")
            c = config.current().get("edges") or {}
            ek = serialization.load_der_public_key(base64.b64decode(t["ek_public"]))
            try:
                A.check_ek(ek, t["ek_sha256"], base64.b64decode(t["ek_cert"]) if t.get("ek_cert") else None,
                           [str(x).encode() for x in c.get("ek_roots") or []],
                           [str(x).encode() for x in c.get("ek_intermediates") or []], at=now)
            except A.AttestError as x:
                raise EdgeRefused(f"the TPM's endorsement key does not hold: {x}") from None
            ak = A.parse_public(base64.b64decode(t["ak_public"]))
            secret = secrets.token_bytes(32)
            idobj, encsec = A.make_credential(A.Public(b"", A.ALG_RSA, A.ALG_SHA256, 0, ek), ak.name, secret)
            self._write("challenges.json", {**self._read("challenges.json"), edge_id: {
                "sha256": hashlib.sha256(secret).hexdigest(), "at": E._iso(now), "ak_name": ak.name.hex()}})
            b = lambda x: base64.b64encode(x).decode()   # noqa: E731
            return {"edge": edge_id, "id_object": b(idobj), "encrypted_secret": b(encsec),
                    "credential": b(A.credential_file(idobj, encsec)), "minutes": self.CHALLENGE_MINUTES}

    def attest_activate(self, edge_id: str, secret_b64: str) -> dict:
        """Credential activation, step two: only the TPM holding the pinned EK and this AK recovers the challenge; the
        activation is recorded in the log (both HA nodes read it), or in the signer's file without one."""
        import base64
        import binascii
        import hashlib
        import hmac
        from datetime import timedelta

        from keyclerk import edge as E
        with self.lock:
            now = self.clock()
            held = self._read("challenges.json")
            ch = held.get(edge_id)
            if not ch or E._ts(ch["at"]) < now - timedelta(minutes=self.CHALLENGE_MINUTES):
                raise EdgeRefused("no challenge waits for this edge at this signer: ask for one first")
            try:
                got = base64.b64decode(str(secret_b64), validate=True)
            except (binascii.Error, ValueError):
                raise EdgeRefused("secret: base64") from None
            self._write("challenges.json", {k: v for k, v in held.items() if k != edge_id})
            if not hmac.compare_digest(hashlib.sha256(got).hexdigest(), ch["sha256"]):
                raise EdgeRefused("a wrong answer: the attestation key is not in the TPM the officer pinned; ask for a "
                                  "new challenge")
            rec = {"activation_id": f"{edge_id}.{ch['ak_name'][:32]}", "edge": edge_id, "ak_name": ch["ak_name"],
                   "at": E._iso(now)}
            if self.record is not None:
                doc = self._records()
                if not any(x["activation_id"] == rec["activation_id"] for x in doc.get("edge_activations", [])):
                    self.record([{"op": "put", "kind": "edge_activations", "key": rec["activation_id"], "record": rec}],
                                "edge_activation")
            else:
                self._write("activations.json", {**self._read("activations.json"), edge_id: rec})
            return {"edge": edge_id, "activated": True}

    def _activated(self, doc: dict, edge_id: str, ak_name: str) -> bool:
        if self.record is not None:
            return any(x["edge"] == edge_id and x["ak_name"] == ak_name for x in doc.get("edge_activations", []))
        return (self._read("activations.json").get(edge_id) or {}).get("ak_name") == ak_name

    def attested(self, e: dict, quote, request, now) -> tuple[str, list[str]]:
        """The profile this edge proved, judged here (0.29 review S12; decision 0016): assured only when the quote
        verifies under the attestation key in the signer's own records, is bound to the edge's signed request (seconds,
        nonce) that is at most QUOTE_FRESH_SECONDS old by this signer's clock, shows the PCR baseline the officer
        signed, and the endorsement key holds under the configured manufacturer roots where they are required. The
        desk's claim is never taken. Credential activation stays the desk's (a residual, recorded)."""
        import base64

        from cryptography.hazmat.primitives import serialization

        from keyclerk import attest as A
        from keyclerk import config
        from keyclerk import edge as E
        from keyclerk import policy_wasm
        t = e.get("tpm")
        if not t:
            return "basic", ["enrolled without a TPM"]
        if not quote or not isinstance(request, (list, tuple)) or len(request) != 2:
            return "basic", ["no quote with this pull (KeyClerk-Quote)"]
        try:
            seconds, nonce = int(request[0]), str(request[1])
        except (TypeError, ValueError):
            return "basic", ["the pull's request time does not read"]
        if abs(now.timestamp() - seconds) > self.QUOTE_FRESH_SECONDS:
            return "basic", [f"the quote's request is more than {self.QUOTE_FRESH_SECONDS} s from the signer's clock"]
        try:
            ak = A.parse_public(base64.b64decode(t["ak_public"]))
            if not self._activated(self._records(), e["edge_id"], ak.name.hex()):     # D3: activation, in the signer
                return "basic", ["the attestation key is not activated at the signer (GET /edge/attest/challenge)"]
            msg, sig, values = E.parse_quote_header(quote)
            facts = A.verify_quote_values(ak, msg, sig, values, A.quote_nonce(e["edge_id"], seconds, nonce))
            c = config.current().get("edges") or {}
            ek = serialization.load_der_public_key(base64.b64decode(t["ek_public"]))
            ek_facts = A.check_ek(ek, t["ek_sha256"], base64.b64decode(t["ek_cert"]) if t.get("ek_cert") else None,
                                  [str(x).encode() for x in c.get("ek_roots") or []],
                                  [str(x).encode() for x in c.get("ek_intermediates") or []], at=now)
        except (A.AttestError, ValueError, KeyError, TypeError) as x:
            return "basic", [f"the quote does not hold at the signer: {x}"]
        d = policy_wasm.edge("attestation", {"quote": facts, "baseline": t["pcr_baseline"],
                                             "ek_certified": bool(ek_facts.get("ek_certified"))})
        why = sorted(d["refusals"])
        return ("basic", why) if why else ("assured", [])

    def seal_bundle(self, edge_id: str, serial: int, sealed_ceiling, policy: dict, attested: str,
                    first_seen: dict | None, identity_map, quote=None, request=None) -> dict:
        from keyclerk import edge as E
        from keyclerk import edge_grants, edge_records, policy_wasm
        if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
            raise EdgeRefused("a bundle's serial is a positive whole number")
        if attested not in ATTESTED:
            raise EdgeRefused(f"attested is one of {ATTESTED}")
        if not isinstance(policy, dict):
            raise EdgeRefused("policy is the bundle's policy references, an object")
        with self.lock:
            now = self.clock()
            doc = self._records()
            e = self._edge(doc, edge_id, now)
            last = int(self._serials().get(edge_id, 0))
            serial = max(serial, last + 1)               # never back: a desk whose edge state was restored older moves up
            names = self.names(identity_map)
            cur = edge_records.current(doc, e, now)
            attested, attest_why = self.attested(e, quote, request, now)   # S12: proved here, never the desk's claim
            settings = policy_wasm.edge("settings", {})
            ceiling, why = None, []
            if edge_records.officer_errors(doc, e, now):
                why = ["the edge's officer is not independent of the core: no leases"]
            elif sealed_ceiling is not None:                 # never an older ceiling than one already sealed: a wider
                floor = int(self._read("ceilings.json").get(edge_id, 0))   # one the officer replaced comes back
                errs, inner = E.check_ceiling(edge_id, cur["officer_key"], sealed_ceiling, floor=floor)
                if errs:
                    why = [f"the ceiling is refused: {errs[0]}"]
                else:
                    ceiling = E.opened(sealed_ceiling)
                    if inner["serial"] > floor:
                        self._write("ceilings.json", {**self._read("ceilings.json"), edge_id: inner["serial"]})
                    self._write("ceiling-" + _safe(edge_id) + ".json", sealed_ceiling)   # what an e-mail answer is held to
            seen = {}
            for lid, at in (first_seen or {}).items():
                try:
                    if E._ts(at) <= now:
                        seen[str(lid)] = E._iso(E._ts(at))
                except (TypeError, ValueError):
                    continue                           # a first-seen time that does not read is now
            got = edge_grants.entries(doc, cur, now, settings, ceiling, attested, names, seen)
            self._write("attested.json", {**self._read("attested.json"), edge_id: attested})   # what carried is held to
            out = E.build_bundle(edge_id, serial, now, settings["horizons"], got["leases"], got["visits"],
                                 got["revoked"], sealed_ceiling if ceiling else None, policy, self.key,
                                 governed_roles=[t["role"] for t in cur["targets"]], records_head=self._head(),
                                 dropped=got["dropped"] + [{"lease_id": None, "why": [w]} for w in why])
            self._write("serials.json", {**self._serials(), edge_id: serial})
            return {"bundle": out, "serial": serial, "leases": got["leases"], "visits": got["visits"],
                    "dropped": got["dropped"], "first_seen": seen, "why": why}


    def _edge(self, doc: dict, edge_id: str, now, ended_ok: bool = False) -> dict:
        from keyclerk import delegation as D
        e = next((x for x in doc.get("edges", []) if x.get("edge_id") == edge_id), None)
        if e is None or (not ended_ok and D._revs(doc, edge_id, now)):
            raise EdgeRefused("no enrolled edge by that id in the signer's records")
        return e

    def seal(self, kind: str, edge_id: str, fields: dict, identity_map=None, verify=None) -> dict:
        """Every other object an edge verifies under the bundle key, each from what the signer's records hold:
        ended (the edge's revocation, naming every node's key), time (the signer's clock), email (a lease that person
        holds on that edge now, the address from the identity map), carried (a visit lease of that person, rebuilt from
        the records), and the acknowledgements, each of what this signer holds itself (0.29 review S2): evidence (the
        edge's chain, continued here), escrow (the two halves' digest and custodians), escrow_confirm (a custodian's own
        fresh sign-in, checked with verify), escrow_status (the confirmations counted here)."""
        from keyclerk import delegation as D
        from keyclerk import edge as E
        from keyclerk import edge_grants, edge_records, policy_wasm
        if not isinstance(fields, dict):
            raise EdgeRefused("fields is an object")
        with self.lock:
            now = self.clock()
            doc = self._records()
            if kind == "ended":
                e = self._edge(doc, edge_id, now, ended_ok=True)
                r = next((r for r in doc.get("admin_revocations", []) if r["id"] == edge_id and D._ts(r["at"]) <= now),
                         None)
                if r is None:
                    raise EdgeRefused(f"{edge_id} is not ended in the signer's records")
                at = D._ts(r["at"])
                return E.ended_notice(self.key, edge_id, at, r.get("reason", ""),
                                      edge_records.node_keys(edge_records.current(doc, e, at)))
            e = edge_records.current(doc, self._edge(doc, edge_id, now), now)
            if kind == "time":
                return E.time_answer(self.key, edge_id, _nonce(fields), now)
            if kind == "email":
                from keyclerk import identity_map as M
                lease_id = fields.get("lease_id")
                if edge_records.officer_errors(doc, e, now):
                    raise EdgeRefused("this edge's officer is not independent of the core: no addresses")
                sealed = self._read("ceiling-" + _safe(edge_id) + ".json") or None
                errs, _ = E.check_ceiling(edge_id, e["officer_key"], sealed,
                                          floor=int(self._read("ceilings.json").get(edge_id, 0))) \
                    if sealed else (["no ceiling sealed"], None)
                got = edge_grants.entries(doc, e, now, policy_wasm.edge("settings", {}), E.opened(sealed), None, {}) \
                    if not errs else {"leases": []}
                live = next((x for x in got["leases"] if x["lease_id"] == lease_id), None)
                if live is None:                         # S11: exactly the leases a bundle would carry now
                    raise EdgeRefused("no lease by that id on this edge now")
                m = self.identity(identity_map)
                email = M.emails(m).get(live["person"]) if m else None
                return E.email_answer(self.key, edge_id, lease_id, live["person"], email, _nonce(fields), now)
            if kind == "carried":
                return self._carried(doc, e, edge_id, fields, identity_map, now, verify)
            if kind == "unlock":
                raise EdgeRefused("an unlock is its own operation (unlock), not a sealed object")
            if kind == "evidence":
                return self._evidence(edge_id, fields, now)
            if kind == "escrow":
                return self._escrow(doc, e, edge_id, fields, now)
            if kind == "escrow_confirm":
                return self._escrow_confirm(doc, edge_id, fields, verify, now)
            if kind == "escrow_status":
                item = self._escrow_item(edge_id, fields)
                n = len(item["confirmed"])
                return E.seal(self.key, {"edge": edge_id, "item_id": fields["item_id"], "sha256": item["sha256"],
                                         "confirmed": n >= len(item["custodians"]) == 2, "custodians_confirmed": n},
                              ESCROW_STATUS)
            raise EdgeRefused(f"no such kind {kind!r}")

    def _evidence(self, edge_id: str, fields: dict, now) -> dict:
        """Continue this edge's evidence chain as the signer holds it, and acknowledge only that (S2): a taken-over
        desk cannot have an edge forget recordings the signer never saw. Entries at or below the held sequence are a
        resend (the desk compares their bytes and reports a fork); the first new one must follow the held head. The
        signer keeps the sequence and head only; with entries [] it seals the head it holds."""
        from keyclerk import edge as E
        if set(fields) != {"entries"} or not isinstance(fields["entries"], list) or len(fields["entries"]) > EVIDENCE_BATCH:
            raise EdgeRefused(f"evidence is {{entries: [...]}}, at most {EVIDENCE_BATCH}")
        heads = self._read("evidence.json")
        seq, head = heads.get(edge_id) or [0, "0" * 64]
        for x in fields["entries"]:
            if not isinstance(x, dict) or not EVIDENCE_FIELDS <= set(x) <= EVIDENCE_FIELDS | {"lease_id"} \
                    or not isinstance(x.get("seq"), int) or isinstance(x["seq"], bool):
                raise EdgeRefused("an evidence entry is {seq, prev, sha256, size, session, at, lease_id?}")
            if x["seq"] <= seq:
                continue
            if x["seq"] != seq + 1 or x.get("prev") != head:
                raise EdgeRefused(f"the signer holds this edge's evidence to seq {seq}: entry {x['seq']} does not follow "
                                  "it (the desk sends the entries from there)")
            head, seq = E.sha256(E.canonical(x)), seq + 1
        if [seq, head] != heads.get(edge_id):
            self._write("evidence.json", {**heads, edge_id: [seq, head]})
        return E.seal(self.key, {"edge": edge_id, "up_to_seq": seq, "head": head, "at": E._iso(now)}, EVIDENCE_ACK)

    def _escrow(self, doc: dict, e: dict, edge_id: str, fields: dict, now) -> dict:
        """An escrowed break-glass value as the signer records it (S2): the digest of the two halves it computed
        itself, and the two custodians their keys belong to, each a different person and a designated custodian of
        this edge in the signer's records. A new value under the same item replaces the old and its confirmations."""
        from keyclerk import delegation as D
        from keyclerk import edge as E
        if set(fields) != {"system", "item_id", "envelopes"}:
            raise EdgeRefused("an escrow is {system, item_id, envelopes}")
        envs, item_id, system = fields["envelopes"], fields["item_id"], fields["system"]
        if not isinstance(item_id, str) or not isinstance(system, str) or not isinstance(envs, list) or len(envs) != 2:
            raise EdgeRefused("an escrow is two envelopes, one per custodian, for one system and item")
        _safe(item_id)
        anchors = []
        for x in envs:
            k = next((k for k in doc.get("person_keys", []) if isinstance(x, dict) and k["key_id"] == x.get("key_id")),
                     None)
            if k is None or D._revs(doc, k["key_id"], now):
                raise EdgeRefused("an escrow half goes to a registered person key in the signer's records")
            if not isinstance(x.get("envelope"), dict) or x["envelope"].get("context") != f"escrow:{system}:{item_id}":
                raise EdgeRefused(f"each envelope's context is escrow:{system}:{item_id}")
            anchors.append(k["anchor"])
        if D.same(doc, anchors[0], anchors[1]):
            raise EdgeRefused("two custodians: two different people")
        if not all(any(D.same(doc, a, c) for c in e.get("custodians") or []) for a in anchors):
            raise EdgeRefused("escrow goes only to the edge's designated custodians in the signer's records")
        digest = E.sha256(E.canonical(envs))
        if self.record is not None:                      # D3: in the log, so either HA node answers its status
            eid = f"{edge_id}.{item_id}.{digest[:16]}"
            if not any(x["escrow_id"] == eid for x in doc.get("edge_escrows", [])):
                rec = {"escrow_id": eid, "edge": edge_id, "item_id": item_id, "sha256": digest,
                       "custodians": anchors, "received": E._iso(now)}
                self.record([{"op": "put", "kind": "edge_escrows", "key": eid, "record": rec}], "edge_escrow")
            return E.seal(self.key, {"edge": edge_id, "item_id": item_id, "sha256": digest, "received": E._iso(now)},
                          ESCROW_ACK)
        held = self._read("escrow.json")
        items = dict(held.get(edge_id) or {})
        items.pop(item_id, None)
        while len(items) >= ESCROW_ITEMS:
            done = [k for k, v in items.items() if len(v["confirmed"]) >= len(v["custodians"])]
            if not done:
                raise EdgeRefused(f"{ESCROW_ITEMS} escrowed values of this edge wait for their custodians")
            items.pop(min(done, key=lambda k: items[k]["received"]))
        items[item_id] = {"sha256": digest, "custodians": anchors, "confirmed": {}, "received": E._iso(now)}
        self._write("escrow.json", {**held, edge_id: items})
        return E.seal(self.key, {"edge": edge_id, "item_id": item_id, "sha256": digest, "received": E._iso(now)},
                      ESCROW_ACK)

    def _escrow_item(self, edge_id: str, fields: dict) -> dict:
        """The newest escrow of this item: from the log where there is one (D3), with the custodians who confirmed it;
        otherwise from the signer's own file."""
        if self.record is not None:
            doc = self._records()
            got = [x for x in doc.get("edge_escrows", []) if x["edge"] == edge_id and x["item_id"] == fields.get("item_id")]
            if not got:
                raise EdgeRefused("no escrow by that id from this edge in the signer's records")
            x = max(got, key=lambda r: (str(r["received"]), r["escrow_id"]))
            confirmed = {c["custodian"]: c["at"] for c in doc.get("edge_escrow_confirms", [])
                         if c["escrow_id"] == x["escrow_id"]}
            return {"escrow_id": x["escrow_id"], "sha256": x["sha256"], "custodians": x["custodians"],
                    "confirmed": confirmed, "received": x["received"]}
        item = (self._read("escrow.json").get(edge_id) or {}).get(fields.get("item_id"))
        if item is None:
            raise EdgeRefused("no escrow by that id from this edge in the signer's records")
        return item

    def _escrow_confirm(self, doc: dict, edge_id: str, fields: dict, verify, now) -> dict:
        """A custodian's own confirmation of their half (S2): their fresh sign-in signs escrow_statement for this
        item's digest; counted once per custodian. Without approval proofs nothing is counted, so the edge keeps the
        value: the desk's word that a half was opened is never enough."""
        from keyclerk import delegation as D
        from keyclerk import edge as E
        from keyclerk.approvals import escrow_statement
        if set(fields) != {"item_id", "custodian", "proof"}:
            raise EdgeRefused("a confirmation is {item_id, custodian, proof}")
        if verify is None:
            raise EdgeRefused("an escrow half is confirmed by its custodian's own fresh sign-in: that needs approval "
                              "proofs (approvals.proofs: required); until then the edge keeps the value")
        item = self._escrow_item(edge_id, fields)
        c = next((x for x in item["custodians"] if D.same(doc, x, fields["custodian"])), None)
        if c is None:
            raise EdgeRefused("not a custodian of this escrowed value")
        st = escrow_statement(self.source.realm, edge_id, fields["item_id"], item["sha256"], fields["custodian"])
        if not isinstance(fields["proof"], str) or not fields["proof"]:
            raise EdgeRefused("a confirmation carries the custodian's fresh sign-in")
        try:
            claims = verify(fields["proof"], st, fields["custodian"])
        except Exception as x:   # noqa: BLE001 - any verification failure is a refusal, said plainly
            raise EdgeRefused(f"the custodian's sign-in does not sign this confirmation: {str(x)[:160]}") from None
        _proof_fresh(claims, now)
        if self.record is not None:                      # D3: in the log
            import hashlib as _h
            if c not in item["confirmed"]:
                cid = f"{item['escrow_id']}.{_h.sha256(c.encode()).hexdigest()[:16]}"
                self.record([{"op": "put", "kind": "edge_escrow_confirms", "key": cid,
                              "record": {"confirm_id": cid, "escrow_id": item["escrow_id"], "custodian": c,
                                         "at": E._iso(now)}}], "edge_escrow_confirm")
            return {"item_id": fields["item_id"], "custodians_confirmed": len(set(item["confirmed"]) | {c})}
        held = self._read("escrow.json")
        items = dict(held.get(edge_id) or {})
        item = {**items[fields["item_id"]]}
        item["confirmed"] = {**item["confirmed"], c: item["confirmed"].get(c) or E._iso(now)}
        items[fields["item_id"]] = item
        self._write("escrow.json", {**held, edge_id: items})
        return {"item_id": fields["item_id"], "custodians_confirmed": len(item["confirmed"])}

    def _carried_allowed(self, doc: dict, e: dict, edge_id: str, lease_id: str, now) -> dict:
        """The visit lease as this edge's bundle would carry it now (review S1): its officer independent of the core,
        inside the ceiling the officer signed (the one last sealed, checked again against the officer's key and its
        floor) at the attested profile the last bundle used, its hardware key not ended, and no cross-edge exclusion
        holding the person elsewhere. Anything a bundle would drop is refused here with the same reason."""
        from keyclerk import edge as E
        from keyclerk import edge_grants, edge_records, policy_wasm
        if edge_records.officer_errors(doc, e, now):
            raise EdgeRefused("the edge's officer is not independent of the core: no carried lease")
        cur = edge_records.current(doc, e, now)
        sealed = self._read("ceiling-" + _safe(edge_id) + ".json") or None
        if not sealed:
            raise EdgeRefused("no ceiling the officer signed is held for this edge: no carried lease until a bundle with "
                              "one was sealed")
        errs, _ = E.check_ceiling(edge_id, cur["officer_key"], sealed,
                                  floor=int(self._read("ceilings.json").get(edge_id, 0)))
        if errs:
            raise EdgeRefused(f"the held ceiling is refused: {errs[0]}")
        attested = self._read("attested.json").get(edge_id, "basic")
        got = edge_grants.entries(doc, cur, now, policy_wasm.edge("settings", {}), E.opened(sealed), attested, {}, {})
        kept = next((x for x in got["visits"] if x["lease_id"] == lease_id), None)
        if kept is None:
            why = next((d["why"] for d in got["dropped"] if d["lease_id"] == lease_id), ["it is not this edge's to carry"])
            raise EdgeRefused("this visit lease is not carried: " + "; ".join(why))
        return kept

    def _carried(self, doc: dict, e: dict, edge_id: str, fields: dict, identity_map, now, verify=None) -> dict:
        """A carried visit lease; with verify (approval proofs required), only on the person's own fresh sign-in over
        carried_statement, at most PROOF_MINUTES old and used once (0.29 review S1, the person's proof)."""
        import hashlib
        import secrets
        from datetime import timedelta
        from keyclerk import delegation as D
        from keyclerk import edge as E
        from keyclerk import policy_wasm
        v = next((x for x in doc.get("edge_visit_leases", []) if x["lease_id"] == fields.get("lease_id")), None)
        if v is None or v["edge"] != edge_id or D._revs(doc, v["lease_id"], now) or D._ts(v["until"]) <= now:
            raise EdgeRefused("no live visit lease by that id on this edge in the signer's records")
        used = None
        if verify is not None:
            from keyclerk.approvals import carried_statement
            proof = fields.get("proof")
            if not isinstance(proof, str) or not proof:
                raise EdgeRefused("a carried lease is the person's own signature: they sign in again for it (approval "
                                  "proofs are required)")
            try:
                claims = verify(proof, carried_statement(self.source.realm, edge_id, v["lease_id"], v["person"]),
                                v["person"])
            except Exception as x:   # noqa: BLE001 - any verification failure is a refusal, said plainly
                raise EdgeRefused(f"the person's sign-in does not sign this carried lease: {str(x)[:160]}") from None
            _proof_fresh(claims, now)
            used = {k: t for k, t in self._read("carried-proofs.json").items() if E._ts(t) > now - timedelta(hours=1)}
            sha = hashlib.sha256(proof.encode()).hexdigest()
            if sha in used:
                raise EdgeRefused("this sign-in already carried a lease: each carried lease is a sign-in of its own")
            used[sha] = E._iso(now)
        kept = self._carried_allowed(doc, e, edge_id, v["lease_id"], now)   # review S1: every check a bundle applies
        v = {**v, "ssh_key": kept["ssh_key"]}
        serial = fields.get("carried_serial")
        floors = self._read("carried.json")
        key = f"{edge_id}|{v['person']}"
        if not isinstance(serial, int) or isinstance(serial, bool) or serial <= int(floors.get(key, 0)):
            raise EdgeRefused(f"carried_serial must be above {floors.get(key, 0)} for this person on this edge")
        hours = int(policy_wasm.edge("settings", {})["carried_max_hours"])
        start = max(now, D._ts(v["from"]))
        role = next((t["role"] for t in e["targets"] if t["target"] in v["targets"]), None)
        body = {"edge": edge_id, "lease_id": v["lease_id"], "person": v["person"],
                "username": self.names(identity_map).get(v["person"]), "ssh_key": v["ssh_key"], "targets": v["targets"],
                "role": role, "from": E._iso(start), "until": E._iso(min(D._ts(v["until"]), start + timedelta(hours=hours))),
                "carried_serial": serial, "nonce": secrets.token_hex(8)}
        if used is not None:
            self._write("carried-proofs.json", used)
        self._write("carried.json", {**floors, key: serial})
        return E.seal(self.key, body, E.CARRIED_FORMAT)


UNLOCK_FIELDS = {"approver", "person", "target", "key_fingerprint", "nonce", "minutes", "node", "proof"}


def _unlock(self, edge_id: str, f: dict, verify=None) -> dict:
    """A phoned unlock code (kc-unlock-v2), computed only after the signer's own records allow it: the approver is an
    unlock approver of this edge and not the person, the target is the edge's, the node is the edge's and has an unlock
    key, minutes and the hourly count inside the edge policy; the count is the signer's own. With verify (the
    deployment requires approval proofs), the approver's fresh sign-in must have signed this unlock's statement."""
    from datetime import timedelta
    from keyclerk import delegation as D
    from keyclerk import edge as E
    from keyclerk import edge_records, policy_wasm
    if set(f) - UNLOCK_FIELDS or not {"approver", "person", "target", "key_fingerprint", "nonce", "minutes"} <= set(f):
        raise EdgeRefused(f"an unlock is {sorted(UNLOCK_FIELDS)} (node only for a two-node edge)")
    with self.lock:
        now = self.clock()
        doc = self._records()
        e = edge_records.current(doc, self._edge(doc, edge_id, now), now)
        a, person = f["approver"], f["person"]
        if not isinstance(a, str) or not any(D.same(doc, a, x) for x in e.get("unlock_approvers", [])):
            raise EdgeRefused("only an unlock approver of this edge reads an unlock code")
        if D.same(doc, a, person):
            raise EdgeRefused("an unlock approver never unlocks themselves: a second person reads the code")
        nodes = {E.key_id(e["enrolment_key"]): e.get("unlock_key")}
        if e.get("node2"):
            nodes[E.key_id(e["node2"]["enrolment_key"])] = e["node2"].get("unlock_key")
        node = f.get("node")
        if node is None:
            if len(nodes) > 1:
                raise EdgeRefused("this edge has two nodes: name the node the code is for")
            node = next(iter(nodes))
        if node not in nodes or not nodes[node]:
            raise EdgeRefused("not a node of this edge with an unlock key")
        if f["target"] not in {t["target"] for t in e["targets"]}:
            raise EdgeRefused("not a target of this edge")
        settings = policy_wasm.edge("settings", {})
        m = f["minutes"]
        if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= int(settings["unlock_max_minutes"]):
            raise EdgeRefused(f"minutes: 1 to {settings['unlock_max_minutes']}")
        for k in ("key_fingerprint", "nonce"):
            if not isinstance(f[k], str) or not 0 < len(f[k]) <= (120 if k == "key_fingerprint" else 64):
                raise EdgeRefused(f"{k}: text")
        counts = self._read("unlocks.json")
        if self.record is not None:                      # D3: every node counts the same unlocks, from the log
            recent = [x["at"] for x in doc.get("edge_unlocks", []) if x["edge"] == edge_id
                      and E._ts(x["at"]) > now - timedelta(hours=1)]
        else:
            recent = [x for x in counts.get(_safe(edge_id), []) if E._ts(x) > now - timedelta(hours=1)]
        if len(recent) >= int(settings["unlock_per_hour"]):
            raise EdgeRefused(f"at most {settings['unlock_per_hour']} unlocks an hour for this edge")
        if verify is not None:
            from keyclerk.approvals import unlock_statement
            st = unlock_statement(self.source.realm, edge_id, node, a, person, f["target"], f["key_fingerprint"],
                                  f["nonce"], m)
            if not isinstance(f.get("proof"), str) or not f["proof"]:
                raise EdgeRefused("an unlock is the approver's own signature: sign in again for this unlock (approval "
                                  "proofs are required)")
            try:
                claims = verify(f["proof"], st, a)
            except Exception as x:   # noqa: BLE001 - any verification failure is a refusal, said plainly
                raise EdgeRefused(f"the approver's sign-in does not sign this unlock: {str(x)[:160]}") from None
            _proof_fresh(claims, now)                    # S5: fresh, and used once
            import hashlib
            used = {k: v for k, v in self._read("unlock-proofs.json").items()
                    if E._ts(v) > now - timedelta(hours=1)}
            sha = hashlib.sha256(f["proof"].encode()).hexdigest()
            if sha in used:
                raise EdgeRefused("this sign-in already read an unlock code: each code is a sign-in of its own")
            used[sha] = E._iso(now)
        own = self.unlock_private
        try:
            code = E.unlock_code(E.unlock_secret(own, E.unlock_public(own), nodes[node], edge_id, node),
                                 edge_id, node, person, f["key_fingerprint"], f["target"], f["nonce"], m)
        except ValueError as x:
            raise EdgeRefused(f"unlock: {x}") from None
        if verify is not None:
            self._write("unlock-proofs.json", used)
        if self.record is not None:
            import secrets as _s
            uid = "UL-" + _s.token_hex(8)
            self.record([{"op": "put", "kind": "edge_unlocks", "key": uid, "record": {
                "unlock_id": uid, "edge": edge_id, "node": node, "approver": a, "person": person,
                "target": f["target"], "minutes": m, "at": E._iso(now)}}], "edge_unlock")
        else:
            self._write("unlocks.json", {**counts, edge_id: recent + [E._iso(now)]})
        return {"code": code, "node": node, "minutes": m}


def _safe(edge_id: str) -> str:
    import re
    if not isinstance(edge_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", edge_id):
        raise EdgeRefused("an edge id is 1 to 64 letters, digits, dots, dashes or underscores")
    return edge_id


def _nonce(fields: dict) -> str:
    n = fields.get("nonce")
    if not isinstance(n, str) or not 0 < len(n) <= 64:
        raise EdgeRefused("a nonce: the edge's signed request, 1 to 64 characters")
    return n


EdgeSealer.unlock = _unlock
