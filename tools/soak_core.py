# SPDX-License-Identifier: EUPL-1.2
"""The core side of an edge soak (roadmap step 7): a realm in HA mode on loopback, for an external edge agent.

    python tools/soak_core.py up --dir DIR [--minutes 60] [--every 150] [--port 8470] [--host desk.soak]
    python tools/soak_core.py check --dir DIR [--agent-log FILE]
    python tools/soak_core.py down --dir DIR

`up` builds a fresh realm from the test fixture (approvals.proofs off, no broker), switches core HA on with the two
people's confirmations (decision 0031 point 10), seeds the commit witness from the stopped signer and starts it, two
signer nodes (node-a, node-b) and the desk's edge API following the active node. It enrols one assured edge,
`plant-a` (profile --profile, basic by default), sets its ceiling, registers two people's keys and writes the
bastion account of each person (DIR/broker/usernames.json and the sealed identity-map.json, as the reconciler
would, under DIR/reconciler.key, which the signers pin), then writes DIR/edge.json: everything an agent needs (the desk URL, the edge's private key, the bundle key to pin, an object whose "key" is the hex, and the officer's key).
Then, every --every seconds, it does one thing at random and logs it to DIR/schedule.jsonl: grant a lease whose end
falls 3 to 8 minutes out or whose start falls 2 to 6 minutes out, end a live one early, kill the active signer node
(restarted after 90 s), or cut the edge off for one interval (the desk then closes every edge connection). The run
ends after --minutes, or on Ctrl-C.

--grants leases (the default) grants ordinary leases: a membership in `admins`, which carries the edge target's
entitlement, for a person without one, ended early by ending the membership. A membership lasts whole days from the
desk's now, so for the grant alone the harness shifts the desk's clock (only on the thread that grants: a bundle
served meanwhile is judged at the real time): a day less N minutes back for an end N minutes out, K minutes forward
for a start K minutes out. --grants visits grants visit leases instead, which need --profile assured.

`check` reads what the run left: no fork alarm at the desk's follower, no inconsistency at the commit witness, every
link the desk adopted committed, and, given the agent's admission log (JSON lines {"at", "lease_id", "admitted"},
times in UTC), no lease admitted before its start, at or after its end + 2 x skew (edge protocol 1.5, section 1),
or after its revocation + 2 x skew once the edge was connected. It exits 1 on any breach and prints each one.

Every process a run starts is recorded in DIR/pids.json. `up` stops them on any exit it sees; on Linux they also die
with the harness (PR_SET_PDEATHSIG). Where the harness itself is killed, `down` stops exactly the recorded processes
whose command line still names DIR (so a reused process id is never touched), and `up` refuses a directory whose
recorded processes still run.

For tests and soaks only: the realm is the test fixture's, its keys sit in DIR, and approvals carry no proofs."""
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import threading
from threading import local as thread_local
import time
import traceback
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from keyclerk import api, commit_witness as C, config, edge as E, ha as HA, relay as R  # noqa: E402
from keyclerk.desk import Desk, Store  # noqa: E402
from keyclerk.signer import Signer, SignerClient  # noqa: E402
from keyclerk.store import note as N, replay  # noqa: E402
from keyclerk.store.log_desk import LogStore  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
ORIGIN, WITNESS = "keyclerk.example/soak", "witness.example/commit"
# The fixture's people, by name. The change log names them by internal anchor (decision 0028) and this desk follows
# the signer without the identity provider's mapping, so the soak looks their anchors up by name (people()).
OWNER, INGRID, EVA, FINN, ANN, GINA = "owner", "ingrid", "eva", "finn", "ann", "gina"
ANCHOR: dict[str, str] = {}
W = lambda name: {"anchor": ANCHOR[name], "roles": []}   # noqa: E731
SKEW = timedelta(seconds=E.SKEW)
EDGE, TARGET = "plant-a", "plc-ssh"
SSH = {FINN: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk4bU2mPbJ6n0dO0eWq5d0q8v0k9s7rT1c2x3y4z5a6 finn@soak",
       ANN: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC5p2nQ9v8w1x3y4z5a6b7c8d9e0f1g2h3i4j5k6l7m8 ann@soak"}


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _t(v):
    """A record's time: the change log's records give text, the desk's own values datetimes."""
    return E._ts(v) if isinstance(v, str) else v


def _iso(t):
    return _t(t).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hex(key):
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _load(path):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(path).read_text(encoding="utf-8").strip()))


def _log(d, kind, **kw):
    line = {"at": _iso(_now()), "kind": kind, **kw}
    with open(d / "schedule.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    print(json.dumps(line), flush=True)


def _verify(token, nonce, by):
    t = json.loads(token)
    if t["nonce"] != nonce or t["by"] != by:
        raise ValueError("this proof is for another statement")


def build(d: Path) -> dict:
    """A fresh realm with HA on and its commit witness seeded, from the stopped signer (the runbook's order)."""
    if d.exists() and any(d.iterdir()):
        raise SystemExit(f"{d} is not empty: a soak starts from a fresh directory")
    d.mkdir(parents=True, exist_ok=True)
    key, wkey, edge_key, officer, rec = (Ed25519PrivateKey.generate() for _ in range(5))
    for name, k in (("signer.key", key), ("witness.key", wkey), ("edge.key", edge_key), ("officer.key", officer),
                    ("reconciler.key", rec)):            # the reconciler's key seals the identity map (0021 point 2)
        (d / name).write_text(_hex(k), encoding="utf-8")
    (d / "reconciler.pub").write_text(E.public_hex(rec), encoding="utf-8")      # the signers' --identity-key
    (d / "token").write_text("soak-" + _hex(Ed25519PrivateKey.generate())[:32], encoding="utf-8")
    cfg = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    cfg["store"] = {"kind": "sqlite"}
    (d / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    config.configure(d / "config.yaml")             # the signers and the desk read the same configuration
    signer = Signer(key, d / "node-a")
    Store(d / "seed-desk", None, _records(d), signer=signer).close()
    signer.migrate()
    signer.background_check()
    from keyclerk.edge_sealer import EdgeSealer       # HA nodes share one bundle key (0021): made once, imported;
    E.load_or_make_key(d / "bundle.key", allow_create=True)   # node-b is copied from node-a below, key included
    EdgeSealer(d / "node-a", None).import_key(d / "bundle.key")
    hcfg = {"origin": ORIGIN, "commit_witness": N.vkey(WITNESS, N.COSIGNATURE, N.raw_public(wkey)),
            "nodes": ["node-a", "node-b"]}
    root = replay.records(signer.replica)["root"]
    size, head = signer.replica.size(), signer.replica.head().hex()
    proofs = [(by, json.dumps({"nonce": HA.statement("example", by, "set", size, head, hcfg, None), "by": by}))
              for by in (root["officer"], root["holders"][0]["anchor"])]
    signer.ha_change("set", hcfg, None, proofs, _verify)
    pub = signer.public_key()
    signer.close()
    C.export_seed(d / "node-a", key, ORIGIN, d / "seed")
    C.reseed(d / "cw", ORIGIN, pub, d / "seed" / "links.jsonl", "soak", "HA on for the soak", lambda: int(time.time()),
             (d / "seed" / "checkpoint.note").read_text(encoding="utf-8"), wkey, WITNESS)
    shutil.copytree(d / "node-a", d / "node-b")
    shutil.rmtree(d / "seed-desk")
    return {"key": key, "edge_key": edge_key, "officer": officer}


class Core:
    """The witness and the two signer nodes as processes; which node answers decides which is active."""

    def __init__(self, d: Path, port: int):
        self.d, self.ports = d, {"witness": port + 1, "node-a": port + 2, "node-b": port + 3}
        self.procs: dict[str, subprocess.Popen] = {}
        key = _load(d / "signer.key")
        self.log_vkey = N.vkey(ORIGIN, N.LOG, N.raw_public(key))

    def argv(self, name):
        py, d = sys.executable, self.d
        if name == "witness":
            return [py, "-m", "keyclerk.witness", "serve", "--commit", "--key", str(d / "witness.key"), "--name", WITNESS,
                    "--state", str(d / "cw"), "--log", self.log_vkey, "--listen", f"127.0.0.1:{self.ports['witness']}"]
        return [py, "-m", "keyclerk.signer", "--key", str(d / "signer.key"), "--state", str(d / name),
                "--config", str(d / "config.yaml"), "--listen", f"tcp:127.0.0.1:{self.ports[name]}",
                "--token", str(d / "token"), "--ha-node", name,
                "--commit-witness", f"http://127.0.0.1:{self.ports['witness']}", "--ha-hold", "5",
                "--identity-key", str(d / "reconciler.pub")]

    def start(self, name):
        out = open(self.d / f"{name}.out", "a", encoding="utf-8")
        self.procs[name] = subprocess.Popen(self.argv(name), cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                                            preexec_fn=_die_with_parent if sys.platform == "linux" else None)
        self._record()

    def kill(self, name):
        p = self.procs.pop(name, None)
        if p and p.poll() is None:
            p.kill()
            p.wait(10)
        self._record()

    def _record(self):
        (self.d / "pids.json").write_text(json.dumps({n: p.pid for n, p in self.procs.items()}), encoding="utf-8")

    def addresses(self):
        return f"tcp:127.0.0.1:{self.ports['node-a']},tcp:127.0.0.1:{self.ports['node-b']}"

    def node_of(self, address):
        return next(n for n in ("node-a", "node-b") if address.endswith(f":{self.ports[n]}"))

    def stop(self):
        for n in list(self.procs):
            self.kill(n)


def _die_with_parent():
    """In the child, on Linux: SIGKILL when the harness dies, so a killed harness leaves no node behind."""
    import ctypes
    import signal
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)          # PR_SET_PDEATHSIG


def _cmdline(pid: int) -> str | None:
    """A running process's command line, or None when no such process runs."""
    if sys.platform == "linux":
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            return None
    if sys.platform == "win32":
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        return out or None
    out = subprocess.run(["ps", "-o", "command=", "-p", str(int(pid))], capture_output=True, text=True).stdout.strip()
    return out or None


def _recorded(d: Path) -> dict[str, int]:
    """The recorded processes of a run in d that still run as that run's (their command line names d)."""
    try:
        pids = json.loads((d / "pids.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {n: pid for n, pid in pids.items() if str(d) in (_cmdline(pid) or "")}


def down(a):
    d = Path(a.dir).resolve()
    left = _recorded(d)
    for name, pid in left.items():
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            os.kill(pid, 9)
        print(f"stopped {name} ({pid})")
    (d / "pids.json").write_text("{}", encoding="utf-8")
    if not left:
        print("nothing of this run was running")
    return 0


def _retry(fn, what, seconds=60):
    """A node becomes active after its hold time; until then the desk's calls are refused or unanswered."""
    end, last = time.monotonic() + seconds, None
    while time.monotonic() < end:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - shown when it does not pass in time
            last = e
            time.sleep(1)
    raise SystemExit(f"{what} did not succeed within {seconds} s: {last}")


def _change(desk: Desk, who: str, body: dict, what: str) -> dict:
    """Propose, and approve as the security officer when a second key is asked; again once when the records moved
    under the proposal (the follower refreshed meanwhile: nothing was signed)."""
    for attempt in (1, 2):
        try:
            r = _applied(desk.propose(W(who), body), what)
            if r["outcome"] == "pending":
                r = _applied(desk.approve(W(INGRID), r["change_id"]), f"approve: {what}")
            return r
        except Exception as e:  # noqa: BLE001 - only the race is tried again
            if attempt == 2 or "records changed while" not in str(e):
                raise
            desk.store.refresh()


def _applied(r, what):
    if r.get("outcome") not in ("applied", "pending"):
        raise RuntimeError(f"{what}: {r}")
    return r


def people(desk: Desk) -> None:
    for p in desk.store.load().get("persons", []):
        ANCHOR[p["person"]] = p["anchors"][0]


def enrol(desk: Desk, keys: dict, profile: str):
    officer, edge_key = keys["officer"], keys["edge_key"]
    people(desk)
    st = E.officer_statement(EDGE, ANCHOR[EVA], E.public_hex(officer), [E.node(E.public_hex(edge_key), None, None)], "enrolment")
    st = E.cosign(edge_key, E.cosign(officer, st))
    r = _applied(desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": EDGE, "enrolment_key": E.public_hex(edge_key),
                                         "officer": ANCHOR[EVA], "officer_key": E.public_hex(officer), "profile": profile,
                                         "statement": st, "custodians": [ANCHOR[FINN], ANCHOR[GINA]],
                                         "targets": [{"target": TARGET, "role": "operator", "entitlement": "admin-console",
                                                      "max_session_hours": 2}]}), "enrol")
    _applied(desk.approve(W(INGRID), r["change_id"]), "approve the enrolment")
    out = {}
    for i, who in enumerate((FINN, ANN)):
        _, pub = R.person_key_from_prf(bytes([0x31 + i]) * 32)
        r = _applied(desk.propose(W(who), {"action": "enrol_person_key", "public_key": R.b64e(pub), "ssh_key": SSH[who],
                                           "user_verification": True}), "person key")
        _applied(desk.approve(W(INGRID), r["change_id"]), "approve the person key")
        out[who] = SSH[who]
    persons = sorted(ANCHOR.values())
    ceiling = {"format": E.CEILING_FORMAT, "edge": EDGE, "serial": 1, "persons": persons, "roles": ["admins"],
               "targets": [TARGET], "classes": ["low", "elevated", "privileged"], "max_lease_hours": 24 * 120,
               "max_offline_hours": 72, "profile": profile, "remote_reach": "off", "ports": [22],
               "signed_at": _iso(_now())}
    desk.set_ceiling(W(EVA), EDGE, {"ceiling": E.seal_ceiling(officer, ceiling)})
    return out


def grant(desk: Desk, d: Path, person: str):
    """A visit lease of one hour whose end falls within minutes, or whose start does: both edges of a window soon."""
    now = _now()
    if random.random() < 0.5:
        start = now - timedelta(hours=1) + timedelta(minutes=random.randint(3, 8))          # ends in 3 to 8 minutes
    else:
        start = now + timedelta(minutes=random.randint(2, 6))                               # starts in 2 to 6 minutes
    _change(desk, OWNER, {"action": "grant_visit_lease", "edge": EDGE, "person": ANCHOR[person], "ssh_key": SSH[person],
                          "targets": [TARGET], "hours": 1, "from": _iso(start)}, "grant")
    lease = _latest_lease(desk)
    _log(d, "grant", lease_id=lease["lease_id"], person=person, **{"from": _iso(lease["from"]),
                                                                   "until": _iso(lease["until"])})


def _latest_lease(desk: Desk):
    doc = desk.store.load()
    return sorted(doc.get("edge_visit_leases", []), key=lambda v: v["lease_id"])[-1]


def _live(desk: Desk):
    doc, now = desk.store.load(), _now()
    ended = {e["id"] for e in doc.get("admin_revocations", [])}
    return [v for v in doc.get("edge_visit_leases", []) if _t(v["until"]) > now and v["lease_id"] not in ended]


class Cut:
    """The edge cut off from the desk: every edge request is dropped while it is set."""
    on = False


def _handler(desk, host):
    base = api.handler(desk, None, {host}, (), False)

    class H(base):
        def handle_one_request(self):
            if Cut.on:
                self.close_connection = True
                return
            return super().handle_one_request()
    return H


class ShiftClock:
    """The desk's clock: the real time, shifted only on the thread that set a shift (a grant), never elsewhere."""

    def __init__(self):
        self.per_thread = thread_local()

    def __call__(self):
        return datetime.now(timezone.utc).replace(microsecond=0) + getattr(self.per_thread, "offset", timedelta(0))

    def shifted(self, offset: timedelta):
        clock = self

        class Shift:
            def __enter__(self):
                clock.per_thread.offset = offset

            def __exit__(self, *exc):
                clock.per_thread.offset = timedelta(0)
        return Shift()


POOL = tuple(f"soak-{i:02d}" for i in range(1, 41))   # people the harness adds to the fixture, for leases


def _lease_id(person_anchor: str, membership_id: str) -> str:
    """The lease id the desk derives for one direct membership (Desk._edge_leases)."""
    return "L-" + E.sha256(f"{EDGE}|{TARGET}|{person_anchor}|admins|{membership_id}".encode())[:16]


def _records(d: Path) -> Path:
    """The fixture's records with the soak's pool of people added: each lease goes to someone without a membership
    in the past day (the clock shift judges an end-soon grant a day back, where a later membership still holds)."""
    doc = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    doc["persons"] += [{"person": p, "kind": "tenant", "anchors": [f"idp:{i:04x}-{p}"]} for i, p in enumerate(POOL, 0x5000)]
    out = d / "records.yaml"
    out.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return out


def _live_memberships(desk: Desk) -> list[dict]:
    doc, now = desk.store.load(), _now()
    ended = {r["id"] for r in doc.get("admin_revocations", [])}
    mine = {ANCHOR[p] for p in POOL}
    return [m for m in doc.get("memberships", []) if m["group"] == "admins" and m["member"].get("anchor") in mine
            and m["membership_id"] not in ended and _t(m["end"]) > now]


def grant_lease(desk: Desk, d: Path, clock: ShiftClock):
    doc, day_ago = desk.store.load(), _now() - timedelta(days=1, minutes=10)
    used = {m["member"].get("anchor") for m in doc.get("memberships", [])
            if m["group"] == "admins" and _t(m["end"]) > day_ago}
    free = [p for p in POOL if ANCHOR[p] not in used]
    if not free:
        _log(d, "skip", why="every pool person holds a live lease")
        return
    person = random.choice(free)
    if random.random() < 0.5:
        offset = -timedelta(days=1) + timedelta(minutes=random.randint(3, 8))                # ends 3 to 8 minutes out
    else:
        offset = timedelta(minutes=random.randint(2, 6))                                      # starts 2 to 6 minutes out
    with clock.shifted(offset):
        _change(desk, OWNER, {"action": "add_member", "group": "admins", "anchor": ANCHOR[person], "days": 1,
                              "reason": "soak: a lease of minutes"}, "grant")
    m = next(m for m in _live_memberships(desk) if m["member"]["anchor"] == ANCHOR[person])
    _log(d, "grant", lease_id=_lease_id(ANCHOR[person], m["membership_id"]), membership_id=m["membership_id"],
         person=person, **{"from": _iso(m["start"]), "until": _iso(m["end"])})


def end_lease(desk: Desk, d: Path):
    live = _live_memberships(desk)
    if not live:
        return
    m = random.choice(live)
    _change(desk, OWNER, {"action": "end_membership", "membership_id": m["membership_id"], "reason": "soak: ended early"},
            "end")
    _log(d, "end", lease_id=_lease_id(m["member"]["anchor"], m["membership_id"]), membership_id=m["membership_id"])


def _probe(base: str, host: str, edge_key) -> dict:
    """One signed bundle request as the edge makes it, verified: edge.json is usable before an agent is pointed at it."""
    import urllib.error
    import urllib.request
    path = "/api/v1/edge/bundle"
    req = urllib.request.Request(base + path, headers={"Host": host,
                                                       "KeyClerk-Edge": E.sign_request(edge_key, EDGE, "GET", path, b"")})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            sealed = json.loads(r.read())
    except urllib.error.HTTPError as e:              # the desk's reason, not only its status
        raise RuntimeError(f"the desk answered {e.code}: {e.read()[:600].decode('utf-8', 'replace')}") from None
    body = E.unseal(sealed, sealed["key"], E.BUNDLE_FORMAT)
    return {"serial": body.get("serial"), "ceiling": body.get("ceiling") is not None,
            "leases": sorted(x["lease_id"] for x in body.get("leases") or []),
            "visit_leases": sorted(x["lease_id"] for x in body.get("visit_leases") or []),
            "without_username": sorted(x["lease_id"] for x in (body.get("leases") or []) + (body.get("visit_leases") or [])
                                       if not x.get("username"))}


def _matches(d: Path, desk: Desk, probe: dict, grants: str) -> dict:
    """Whether the bundle names exactly the leases the schedule says are live now: the lease ids check relies on."""
    if grants == "leases":
        ms, now = _live_memberships(desk), _now()
        live = {_lease_id(m["member"]["anchor"], m["membership_id"]) for m in ms if _t(m["start"]) <= now}
        future = {_lease_id(m["member"]["anchor"], m["membership_id"]) for m in ms if _t(m["start"]) > now}
        got = set(probe["leases"]) & _scheduled(d)
        return {"without_username": probe.get("without_username", []),
                "missing": sorted(live - got), "unexpected": sorted(got - live - future),
                "future_in_bundle": sorted(got & future), "future_held_back": sorted(future - got)}
    else:
        live = {v["lease_id"] for v in _live(desk)}
        got = set(probe["visit_leases"])
    return {"without_username": probe.get("without_username", []),
            "missing": sorted(live - got), "unexpected": sorted(got - live)}


def _scheduled(d: Path) -> set[str]:
    return {json.loads(x)["lease_id"] for x in (d / "schedule.jsonl").read_text(encoding="utf-8").splitlines()
            if '"grant"' in x}


def up(a):
    d = Path(a.dir).resolve()
    a.profile = a.profile or ("assured" if a.grants == "visits" else "basic")
    if a.grants == "visits" and a.profile != "assured":
        raise SystemExit("visit leases need an assured edge: --profile assured")
    if _recorded(d):
        raise SystemExit(f"processes of an earlier run in {d} still run: python tools/soak_core.py down --dir {d}")
    keys = build(d)
    core = Core(d, a.port)
    try:
        return _run(a, d, keys, core)
    finally:
        core.stop()                                     # never leave a node or the witness behind


def _run(a, d, keys, core):
    core.start("witness")
    time.sleep(1)
    core.start("node-a")
    client = SignerClient(core.addresses(), str(d / "token"))
    _retry(client.ping, "node-a becoming active")      # then node-b, a standby: no election race at the start
    core.start("node-b")
    store = _retry(lambda: LogStore(d / "desk", client), "the desk following a node")
    clock = ShiftClock()
    broker = d / "broker"                              # as the reconciler writes it: anchor -> the bastion account
    broker.mkdir(exist_ok=True)
    desk = Desk(store, broker_state=broker, clock=clock)
    _retry(client.ping, "a node becoming active")       # then enrol once: a retried enrolment repeats its changes
    store.refresh()
    people = enrol(desk, keys, a.profile)
    usernames = {ANCHOR[p]: p for p in POOL + (FINN, ANN)}
    (broker / "usernames.json").write_text(json.dumps(usernames, indent=1), encoding="utf-8")
    from keyclerk import identity_map                  # 0.29.0: the signer names accounts only from the sealed map
    (broker / "identity-map.json").write_text(json.dumps(identity_map.seal(
        _load(d / "reconciler.key"), store.load()["realm"], None, datetime.now(timezone.utc), usernames, {})),
        encoding="utf-8")
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), _handler(desk, a.host))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stop = threading.Event()

    def follow():
        while not stop.is_set():
            try:
                store.refresh()
            except Exception as e:  # noqa: BLE001 - logged; the next refresh tries again
                _log(d, "follow_error", error=str(e)[:200])
            stop.wait(2)
    threading.Thread(target=follow, daemon=True).start()
    (d / "edge.json").write_text(json.dumps({
        "desk": f"http://127.0.0.1:{a.port}", "host": a.host, "edge_id": EDGE, "edge_key": _hex(keys["edge_key"]),
        "bundle_key": desk.edge_key(), "officer_key": E.public_hex(keys["officer"]), "target": TARGET,
        "people": {p: {"anchor": ANCHOR[p], "ssh_key": s} for p, s in people.items()},
        "usernames": {p: p for p in POOL + (FINN, ANN)},   # the accounts leases name: the edge agent creates them
        "skew_seconds": int(SKEW.total_seconds())},
        indent=2), encoding="utf-8")
    probe = _probe(f"http://127.0.0.1:{a.port}", a.host, keys["edge_key"])
    _log(d, "ready", desk=f"http://127.0.0.1:{a.port}", active=core.node_of(client.address), probe=probe)
    end, restart = time.monotonic() + a.minutes * 60, {}
    try:
        while time.monotonic() < end:
            time.sleep(a.every)
            for n, t in list(restart.items()):
                if time.monotonic() >= t:
                    core.start(n)
                    restart.pop(n)
                    _log(d, "restart", node=n)
            if Cut.on:
                Cut.on = False
                _log(d, "reconnect")
                continue
            choice = random.choices(["grant", "end", "kill", "cut"], [4, 2, 1, 1])[0]
            try:
                if choice == "grant" and a.grants == "leases":
                    grant_lease(desk, d, clock)
                elif choice == "end" and a.grants == "leases":
                    end_lease(desk, d)
                elif choice == "grant":
                    grant(desk, d, random.choice(list(people)))
                elif choice == "end" and _live(desk):
                    v = random.choice(_live(desk))
                    _change(desk, OWNER, {"action": "end_edge_record", "id": v["lease_id"],
                                          "reason": "soak: ended early"}, "end")
                    _log(d, "end", lease_id=v["lease_id"])
                elif choice == "kill" and not restart and time.monotonic() + 2 * a.every < end:
                    store.refresh()
                    n = core.node_of(client.address)
                    core.kill(n)
                    restart[n] = time.monotonic() + 90
                    _log(d, "kill", node=n)
                elif choice == "cut":
                    Cut.on = True
                    _log(d, "cut")
            except Exception as e:  # noqa: BLE001 - a refused action during a failover is part of the soak
                _log(d, "refused", action=choice, error=f"{type(e).__name__}: {str(e)[:300]}",
                     trace=traceback.format_exc()[-3000:])
    except KeyboardInterrupt:
        pass
    finally:
        try:
            for n, _ in list(restart.items()):             # a node killed near the end: back, so one is active
                core.start(n)
            def final():
                store.refresh()
                return _probe(f"http://127.0.0.1:{a.port}", a.host, keys["edge_key"])
            _log(d, "bundle", **_matches(d, desk, _retry(final, "the final bundle", 120), a.grants))
        except Exception as e:  # noqa: BLE001 - recorded; check reports it
            _log(d, "bundle", error=str(e)[:300])
        stop.set()
        srv.shutdown()
        _log(d, "done", alarms=getattr(store.follower, "alarms", []))
        store.close()
    return 0


def check(a):
    d, breaches = Path(a.dir).resolve(), []
    sched = [json.loads(x) for x in (d / "schedule.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    done = [s for s in sched if s["kind"] == "done"]
    if not done:
        breaches.append("the run did not finish (no done line)")
    for b in [s for s in sched if s["kind"] == "bundle"]:
        if b.get("error") or b.get("missing") or b.get("unexpected") or b.get("without_username"):
            breaches.append(f"the final bundle does not match the schedule: {b}")
    if done and done[-1].get("alarms"):
        breaches.append(f"the desk's follower raised alarms: {done[-1]['alarms']}")
    ev = d / "cw" / "evidence.jsonl"
    if ev.exists():
        bad = [x for x in ev.read_text(encoding="utf-8").splitlines() if "inconsistent" in x]
        if bad:
            breaches.append(f"the commit witness recorded {len(bad)} inconsistent proposals")
    leases = {s["lease_id"]: s for s in sched if s["kind"] == "grant"}
    ends = {s["lease_id"]: s["at"] for s in sched if s["kind"] == "end"}
    if a.agent_log:
        p = lambda s: datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)  # noqa: E731
        for line in Path(a.agent_log).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            x = json.loads(line)
            if not x.get("admitted") or x["lease_id"] not in leases:
                continue
            at, lz = p(x["at"]), leases[x["lease_id"]]
            if at < p(lz["from"]):
                breaches.append(f"{x['lease_id']} admitted at {x['at']}, before its start {lz['from']}")
            if at >= p(lz["until"]) + 2 * SKEW:
                breaches.append(f"{x['lease_id']} admitted at {x['at']}, past its end {lz['until']} + 2 x skew")
            if x["lease_id"] in ends and at >= p(ends[x["lease_id"]]) + 2 * SKEW:
                breaches.append(f"{x['lease_id']} admitted at {x['at']}, after its end at {ends[x['lease_id']]} + 2 x skew")
    kinds = {}
    for s in sched:
        kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
    print(json.dumps({"events": kinds, "breaches": breaches}, indent=2))
    return 1 if breaches else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python tools/soak_core.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up")
    u.add_argument("--dir", required=True)
    u.add_argument("--minutes", type=float, default=60)
    u.add_argument("--every", type=float, default=150, help="seconds between two actions or faults")
    u.add_argument("--port", type=int, default=8470, help="the desk's port; the witness and nodes take the next three")
    u.add_argument("--host", default="desk.soak", help="the Host header the desk accepts")
    u.add_argument("--grants", choices=("leases", "visits"), default="leases")
    u.add_argument("--profile", choices=("basic", "assured"), default=None,
                   help="the edge's profile: basic for leases, assured (needed) for visit leases")
    c = sub.add_parser("check")
    c.add_argument("--dir", required=True)
    c.add_argument("--agent-log")
    sub.add_parser("down").add_argument("--dir", required=True)
    a = ap.parse_args(argv)
    return {"up": up, "check": check, "down": down}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
