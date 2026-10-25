# SPDX-License-Identifier: EUPL-1.2
"""Compile the policies the engine evaluates in process (decision 0008) to WebAssembly.

    python tools/build_policy.py           build keyclerk/policy/<name>.wasm and its record <name>.wasm.build (JSON; not .json, so OPA never loads it as data)
    python tools/build_policy.py --check   exit 1 when a compiled policy does not belong to its current source

The record names the source's digest, so a changed .rego cannot ship with an old .wasm (a test runs --check). The
build needs the opa CLI; the engine at run time does not.
"""
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

POLICY = Path(__file__).resolve().parent.parent / "keyclerk" / "policy"
BUILDS = {"second_key": "keyclerk/second_key/decision", "view": "keyclerk/view/decision", "tree": "keyclerk/tree/decision",
          "visits": ["keyclerk/visits/act", "keyclerk/visits/entry", "keyclerk/visits/timers", "keyclerk/visits/see",
                     "keyclerk/visits/unescorted", "keyclerk/visits/badge"],
          "identity": ["keyclerk/identity/membership", "keyclerk/identity/reach", "keyclerk/identity/actor"],
          "ceiling": "keyclerk/ceiling/decision",                                                         # decision 0014
          "edge": ["keyclerk/edge/settings", "keyclerk/edge/admit", "keyclerk/edge/visit_window", "keyclerk/edge/attestation"]}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build(name: str, entrypoint: str | list[str]) -> dict:
    src = POLICY / f"{name}.rego"
    points = [entrypoint] if isinstance(entrypoint, str) else entrypoint
    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "bundle.tar.gz"
        # from the policy folder, by file name: the compiler keeps the source's path for its error locations, and an
        # absolute one would carry the build machine's folders (and its user's name) into every module, and make the
        # module's bytes, which edges pin by hash, depend on where it was built
        subprocess.run(["opa", "build", "-t", "wasm", *[x for e in points for x in ("-e", e)], src.name, "-o", str(bundle)],
                       check=True, capture_output=True, cwd=POLICY)
        with tarfile.open(bundle) as t:
            wasm = t.extractfile([m for m in t.getmembers() if m.name.endswith("policy.wasm")][0]).read()
    version = subprocess.run(["opa", "version"], capture_output=True, text=True).stdout.splitlines()[0].split()[-1]
    (POLICY / f"{name}.wasm").write_bytes(wasm)
    record = {"entrypoint": entrypoint, "source_sha256": sha(src.read_bytes().replace(b"\r\n", b"\n")),
              "wasm_sha256": sha(wasm), "opa": version}
    (POLICY / f"{name}.wasm.build").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8", newline="\n")
    return record


def check() -> list[str]:
    errs = []
    for name in BUILDS:
        rec = json.loads((POLICY / f"{name}.wasm.build").read_text(encoding="utf-8"))
        if rec["source_sha256"] != sha((POLICY / f"{name}.rego").read_bytes().replace(b"\r\n", b"\n")):
            errs.append(f"{name}.rego changed since {name}.wasm was built: run python tools/build_policy.py")
        if rec["wasm_sha256"] != sha((POLICY / f"{name}.wasm").read_bytes()):
            errs.append(f"{name}.wasm is not the one its record names")
    return errs


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        errs = check()
        print("\n".join(errs) or "compiled policies match their sources")
        sys.exit(1 if errs else 0)
    for n, e in BUILDS.items():
        print(n, build(n, e))
