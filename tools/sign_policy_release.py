# SPDX-License-Identifier: EUPL-1.2
"""Sign a policy release manifest (decision 0014a): the hashes of the compiled edge modules, signed with a release key
the deployment keeps apart from the bundle key (offline, or in its password manager). The desk ships the manifest from
its store; an edge that pins the release key refuses modules the manifest does not name.

    python tools/sign_policy_release.py --key RELEASE.key --out STORE/policy-release.json
    python tools/sign_policy_release.py --new-key RELEASE.key        (makes a key, 0600, and prints its public half)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from keyclerk import edge as E  # noqa: E402

MODULES = ("edge", "ceiling")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key")
    ap.add_argument("--out")
    ap.add_argument("--new-key")
    a = ap.parse_args(argv)
    if a.new_key:
        k = E.load_or_make_key(Path(a.new_key), allow_create=True)
        print("release key", E.public_hex(k), "key id", E.key_id(E.public_hex(k)))
        return 0
    if not (a.key and a.out):
        ap.error("--key and --out, or --new-key")
    k = E.load_or_make_key(Path(a.key), allow_create=False)
    mods = {m: hashlib.sha256((ROOT / "keyclerk" / "policy" / f"{m}.wasm").read_bytes()).hexdigest() for m in MODULES}
    Path(a.out).write_text(json.dumps(E.sign_release(k, mods), sort_keys=True) + "\n", encoding="utf-8")
    print(a.out, "signed by key id", E.key_id(E.public_hex(k)), mods)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
