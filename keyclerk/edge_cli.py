# SPDX-License-Identifier: EUPL-1.2
"""The edge interface from a terminal (decision 0014, slice C): what an edge agent, an edge's officer and a tester need,
in the reference implementation. `python -m keyclerk.edge_cli COMMAND ...`; every command prints JSON or one line.

One signing mode (amendment 0014d): every signed object is signed over its exact bytes. The officer seals a ceiling;
the officer and each node of the edge cosign one statement. `show` prints what a signed object says before anyone signs.

    keygen OUT                         an Ed25519 key, 0600; prints its public half and key id
    unlock-keygen OUT                  a P-256 phoned-unlock key (kc-unlock-v2), 0600, for an edge without a TPM (with
                                       one, the key is made inside the TPM); prints its public half
    statement --edge E --officer ANCHOR --officer-key HEX --enrolment-key HEX [HEX] [--unlock-key B64 ...]
              [--tpm FILE ...] [--purpose enrolment|rotation]
                                       the kc-edge-officer-v2 statement (a node per enrolment key; two for HA)
    cosign FILE --key KEY              sign a statement (a document, or one others signed) over its bytes; prints the
                                       multi-signed object, and what it says on stderr
    ceiling --edge E --serial N [--persons A ...] [--roles G ...] --targets T ... [--classes C ...]
            [--max-lease-hours H] [--max-offline-hours H] [--profile assured|basic] [--ports P ...]
                                       a ceiling document for the officer to seal
    seal FILE --key KEY                the officer seals a ceiling document (kc-edge-ceiling-v2); what it says on stderr
    show FILE                          what a sealed or multi-signed object says, and whose signatures verify
    request --key KEY --edge E --method M --path P [--body FILE]
                                       the KeyClerk-Edge header for one request
    pull --desk URL --edge E --key KEY [--serial N]
                                       GET /api/v1/edge/bundle, signed; prints the sealed bundle
    verify FILE --pins PINS.json [--state STATE.json] [--now ISO]
                                       verify a sealed bundle with pins {edge, bundle_key, officer_key, release_key};
                                       with --state, store the new state when there are no errors
    encrypt --to PUBLIC_KEY --context C --in FILE
                                       a kc-relay-v1 envelope to a person key
    verify-carried FILE --pins PINS.json [--state STATE.json]
                                       verify a carried visit lease for this edge
    unlock-code --unlock-key FILE --edge-unlock-key B64 --desk-unlock-key B64 --edge E --node KEY_ID --person P
                --fingerprint F --target T --nonce N --minutes M
                                       the code the edge node expects for a phoned unlock (kc-unlock-v2);
                                       FILE holds a P-256 scalar (hex): the edge node's, or the desk's
    module --desk URL --edge E --key KEY --sha256 S --out FILE
                                       fetch a policy module a bundle names and check its bytes against the hash
    verify-ended FILE --pins PINS.json --enrolment-key HEX
                                       verify an ended notice (410) for this node before the agent stops and wipes
    conformance [FILE]                 run tests/conformance/edge.json (or FILE) against the local modules
    simulate --desk URL --edge E --key KEY --pins PINS.json --state STATE.json
                                       one round of an edge: pull, verify, report, and print what an agent would do
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from keyclerk import edge as E
from keyclerk import relay as R


def _out(obj) -> None:
    print(json.dumps(obj, indent=1, sort_keys=True) if not isinstance(obj, str) else obj)


def _key(path: str):
    return E.load_or_make_key(Path(path), allow_create=False)


def _now(s: str | None) -> datetime:
    return datetime.strptime(s, E.ISO).replace(tzinfo=timezone.utc) if s else datetime.now(timezone.utc)


def _http(desk: str, method: str, path: str, edge: str, key, body: bytes = b"", host: str | None = None) -> dict:
    host = host or desk.split("//", 1)[-1].split("/", 1)[0]
    header = E.sign_request(key, edge, method, path, body)
    req = urllib.request.Request(desk.rstrip("/") + path, data=body if method == "POST" else None, method=method,
                                 headers={"KeyClerk-Edge": header, "Host": host, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _show(obj: dict) -> dict:
    """What a signed object says, and which of its signatures verify over its bytes (no key is pinned here)."""
    content = E.opened(obj)
    if "signatures" in obj:
        good = E.multi_signers(obj)
        sigs = [{"key_id": E.key_id(s["key"]), "verifies": s["key"] in good} for s in obj["signatures"]]
    else:
        try:
            E.unseal(obj, obj.get("key"), content.get("format"))
            ok = True
        except ValueError:
            ok = False
        sigs = [{"key_id": obj.get("key_id"), "verifies": ok}]
    return {"says": content, "signatures": sigs}


def _ceiling_check(doc, entry):
    from keyclerk import policy_wasm
    return policy_wasm.ceiling({"ceiling": doc, "entry": entry})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m keyclerk.edge_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen")
    s.add_argument("out")
    s = sub.add_parser("unlock-keygen")
    s.add_argument("out")
    s = sub.add_parser("statement")
    for k in ("--edge", "--officer", "--officer-key"):
        s.add_argument(k, required=True)
    s.add_argument("--enrolment-key", nargs="+", required=True, help="one per node; two for the HA profile")
    s.add_argument("--unlock-key", nargs="*", default=[], help="each node's kc-unlock-v2 public key, in node order")
    s.add_argument("--tpm", nargs="*", default=[],
                   help="JSON files with each node's tpm record (decision 0016), in node order: their commitments are signed")
    s.add_argument("--purpose", default="enrolment", choices=E.STATEMENT_PURPOSES)
    s = sub.add_parser("cosign")
    s.add_argument("file")
    s.add_argument("--key", required=True)
    s = sub.add_parser("seal")
    s.add_argument("file")
    s.add_argument("--key", required=True)
    s = sub.add_parser("show")
    s.add_argument("file")
    s = sub.add_parser("quote-nonce", help="what a pull's quote is over (decision 0016), hex")
    s.add_argument("--edge", required=True)
    s.add_argument("--seconds", type=int, required=True)
    s.add_argument("--nonce", required=True)
    s = sub.add_parser("ceiling")
    s.add_argument("--edge", required=True)
    s.add_argument("--serial", type=int, required=True)
    s.add_argument("--persons", nargs="*", default=[])
    s.add_argument("--roles", nargs="*", default=[])
    s.add_argument("--targets", nargs="+", required=True)
    s.add_argument("--classes", nargs="*", default=["low"])
    s.add_argument("--max-lease-hours", type=int, default=8)
    s.add_argument("--max-offline-hours", type=int, default=24)
    s.add_argument("--profile", default="basic", choices=("assured", "basic"))
    s.add_argument("--remote-reach", default="off", choices=("off", "tunnel", "netbird"))
    s.add_argument("--ports", nargs="*", type=int, default=[22])
    s = sub.add_parser("request")
    for k in ("--key", "--edge", "--method", "--path"):
        s.add_argument(k, required=True)
    s.add_argument("--body")
    s = sub.add_parser("pull")
    for k in ("--desk", "--edge", "--key"):
        s.add_argument(k, required=True)
    s.add_argument("--serial")
    s.add_argument("--host", help="the Host header, when it differs from the URL's")
    s = sub.add_parser("verify")
    s.add_argument("file")
    s.add_argument("--pins", required=True)
    s.add_argument("--state")
    s.add_argument("--now")
    s = sub.add_parser("encrypt")
    for k in ("--to", "--context", "--in"):
        s.add_argument(k, required=True)
    s = sub.add_parser("verify-carried")
    s.add_argument("file")
    s.add_argument("--pins", required=True)
    s.add_argument("--state")
    s = sub.add_parser("unlock-code")
    for k in ("--unlock-key", "--edge-unlock-key", "--desk-unlock-key", "--edge", "--node", "--person", "--fingerprint",
              "--target", "--nonce"):
        s.add_argument(k, required=True)
    s.add_argument("--minutes", type=int, required=True)
    s = sub.add_parser("module")
    for k in ("--desk", "--edge", "--key", "--sha256", "--out"):
        s.add_argument(k, required=True)
    s.add_argument("--host", help="the Host header, when it differs from the URL's")
    s = sub.add_parser("verify-ended")
    s.add_argument("file")
    s.add_argument("--pins", required=True)
    s.add_argument("--enrolment-key", required=True)
    s = sub.add_parser("conformance")
    s.add_argument("file", nargs="?")
    s = sub.add_parser("simulate")
    for k in ("--desk", "--edge", "--key", "--pins", "--state"):
        s.add_argument(k, required=True)
    s.add_argument("--host", help="the Host header, when it differs from the URL's")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        k = E.load_or_make_key(Path(a.out), allow_create=True)
        _out({"public_key": E.public_hex(k), "key_id": E.key_id(E.public_hex(k)), "file": a.out})
    elif a.cmd == "unlock-keygen":
        import os
        scalar = E.new_unlock_private()
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            h.write(scalar)
        _out({"unlock_key": E.unlock_public(E.unlock_private(scalar)), "format": E.UNLOCK_CONTEXT, "file": a.out})
    elif a.cmd == "statement":
        n = len(a.enrolment_key)
        if len(a.unlock_key) > n or len(a.tpm) > n:
            ap.error("at most one --unlock-key and one --tpm per --enrolment-key, in node order")
        tpms = [E.tpm_commitment(json.loads(Path(f).read_text(encoding="utf-8"))) for f in a.tpm]
        nodes = [E.node(k, a.unlock_key[i] if i < len(a.unlock_key) else None, tpms[i] if i < len(tpms) else None)
                 for i, k in enumerate(a.enrolment_key)]
        _out(E.officer_statement(a.edge, a.officer, a.officer_key, nodes, a.purpose))
    elif a.cmd == "cosign":
        obj = json.loads(Path(a.file).read_text(encoding="utf-8"))
        signed = E.cosign(_key(a.key), obj)
        print(json.dumps(_show(signed), indent=1, sort_keys=True), file=sys.stderr)
        _out(signed)
    elif a.cmd == "seal":
        signed = E.seal_ceiling(_key(a.key), json.loads(Path(a.file).read_text(encoding="utf-8")))
        print(json.dumps(_show(signed), indent=1, sort_keys=True), file=sys.stderr)
        _out(signed)
    elif a.cmd == "show":
        _out(_show(json.loads(Path(a.file).read_text(encoding="utf-8"))))
    elif a.cmd == "quote-nonce":
        from keyclerk import attest
        print(attest.quote_nonce(a.edge, a.seconds, a.nonce).hex())
    elif a.cmd == "ceiling":
        _out({"format": E.CEILING_FORMAT, "edge": a.edge, "serial": a.serial, "persons": a.persons, "roles": a.roles,
              "targets": a.targets, "classes": a.classes, "max_lease_hours": a.max_lease_hours,
              "max_offline_hours": a.max_offline_hours, "profile": a.profile, "remote_reach": a.remote_reach,
              "ports": a.ports, "signed_at": datetime.now(timezone.utc).strftime(E.ISO)})
    elif a.cmd == "request":
        body = Path(a.body).read_bytes() if a.body else b""
        _out(E.sign_request(_key(a.key), a.edge, a.method, a.path, body))
    elif a.cmd == "pull":
        path = "/api/v1/edge/bundle" + (f"?serial={a.serial}" if a.serial else "")
        _out(_http(a.desk, "GET", path, a.edge, _key(a.key), host=a.host))
    elif a.cmd == "verify":
        pins = json.loads(Path(a.pins).read_text(encoding="utf-8"))
        state = json.loads(Path(a.state).read_text(encoding="utf-8")) if a.state and Path(a.state).exists() else {}
        errs, applied = E.verify_bundle(json.loads(Path(a.file).read_text(encoding="utf-8")), pins, state, _now(a.now), _ceiling_check,
                                        pins.get("profile"))
        if not errs and a.state:
            Path(a.state).write_text(json.dumps(applied["state"], sort_keys=True), encoding="utf-8")
        _out({"ok": not errs, "errors": errs, "applied": applied})
        return 0 if not errs else 2
    elif a.cmd == "encrypt":
        _out(R.encrypt(a.to, Path(getattr(a, "in")).read_bytes(), a.context))
    elif a.cmd == "verify-carried":
        pins = json.loads(Path(a.pins).read_text(encoding="utf-8"))
        state = json.loads(Path(a.state).read_text(encoding="utf-8")) if a.state and Path(a.state).exists() else {}
        errs, out = E.verify_carried(json.loads(Path(a.file).read_text(encoding="utf-8")), pins, state, datetime.now(timezone.utc))
        if not errs and a.state:
            Path(a.state).write_text(json.dumps({**state, **out["state"]}, sort_keys=True), encoding="utf-8")
        _out({"ok": not errs, "errors": errs, "lease": out.get("lease")})
        return 0 if not errs else 2
    elif a.cmd == "unlock-code":
        own = E.unlock_private(Path(a.unlock_key).read_text(encoding="utf-8").strip())
        secret = E.unlock_secret(own, a.desk_unlock_key, a.edge_unlock_key, a.edge, a.node)
        _out(E.unlock_code(secret, a.edge, a.node, a.person, a.fingerprint, a.target, a.nonce, a.minutes))
    elif a.cmd == "module":
        import base64
        got = _http(a.desk, "GET", f"/api/v1/edge/module/{a.sha256}", a.edge, _key(a.key), host=a.host)
        raw = base64.b64decode(got["wasm"], validate=True)
        errs = E.verify_module(raw, a.sha256)
        if errs:
            _out({"refused": errs})
            return 2
        Path(a.out).write_bytes(raw)
        _out({"name": got["name"], "sha256": a.sha256, "bytes": len(raw), "file": a.out})
    elif a.cmd == "verify-ended":
        pins = json.loads(Path(a.pins).read_text(encoding="utf-8"))
        errs, notice = E.verify_ended(json.loads(Path(a.file).read_text(encoding="utf-8")), pins, a.enrolment_key)
        _out({"ok": not errs, "errors": errs, "notice": notice})
        return 0 if not errs else 2
    elif a.cmd == "conformance":
        f = Path(a.file) if a.file else Path(__file__).resolve().parent.parent / "tests" / "conformance" / "edge.json"
        cases = json.loads(f.read_text(encoding="utf-8"))
        from keyclerk import policy_wasm
        bad = [c["name"] for c in cases["cases"]
               if json.dumps(policy_wasm.load(c["policy"]).eval(c["entrypoint"], c["input"]), sort_keys=True, default=sorted)
               != json.dumps(c["expected"], sort_keys=True, default=sorted)]
        for c in cases.get("verifier", {}).get("cases", []):
            errs, applied = E.verify_bundle(c["sealed"], c["pins"], c["state"], _now(c["now"]))
            if (not errs) != c["expected"]["ok"] or [x["lease_id"] for x in applied.get("leases", [])] != c["expected"]["leases"]:
                bad.append(c["name"])
        from keyclerk import edge_conformance
        bad += edge_conformance.failures(cases)
        _out({"cases": len(cases["cases"]) + edge_conformance.count(cases), "failed": bad})
        return 0 if not bad else 2
    elif a.cmd == "simulate":
        key, pins = _key(a.key), json.loads(Path(a.pins).read_text(encoding="utf-8"))
        state_f = Path(a.state)
        state = json.loads(state_f.read_text(encoding="utf-8")) if state_f.exists() else {}
        sealed = _http(a.desk, "GET", "/api/v1/edge/bundle", a.edge, key, host=a.host)
        errs, applied = E.verify_bundle(sealed, pins, state, datetime.now(timezone.utc), _ceiling_check, pins.get("profile"))
        if errs:
            _out({"refused": errs})
            return 2
        import base64
        cache = Path(str(state_f) + ".modules")          # kept by hash: fetched once per change
        cache.mkdir(exist_ok=True)
        for name, ref in (E.opened(sealed).get("policy") or {}).get("modules", {}).items():
            f = cache / ref["sha256"]
            if not f.exists():
                got = _http(a.desk, "GET", f"/api/v1/edge/module/{ref['sha256']}", a.edge, key, host=a.host)
                raw = base64.b64decode(got["wasm"], validate=True)
                if E.verify_module(raw, ref["sha256"]):
                    _out({"refused": [f"policy module {name}: {x}" for x in E.verify_module(raw, ref["sha256"])]})
                    return 2
                f.write_bytes(raw)
        state_f.write_text(json.dumps(applied["state"], sort_keys=True), encoding="utf-8")
        report = json.dumps({"applied_serial": applied["state"]["serial"], "attestation": {"profile": pins.get("profile", "basic")},
                             "drift": []}).encode()
        _http(a.desk, "POST", "/api/v1/edge/report", a.edge, key, report, host=a.host)
        _out({"serial": applied["state"]["serial"],
              "assign": [{"user": x.get("username") or x["person"], "role": x["role"], "target": x["target"], "until": x["until"],
                          "max_session_hours": x.get("max_session_hours")} for x in applied["leases"]],
              "install_visit_keys": [{"user": x.get("username") or x["person"], "ssh_key": x["ssh_key"][:40] + "...",
                                      "targets": x["targets"], "until": x["until"]} for x in applied["visit_leases"]],
              "end": applied["revoked"], "refused_by_ceiling": applied["refused_by_ceiling"]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
