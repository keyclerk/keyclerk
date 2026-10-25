# SPDX-License-Identifier: EUPL-1.2
"""How long a person waits at the desk for a valid generated organisation of N people (decision 0017): loading the
records, a preview, and a change applied end to end (proposal, checks, signature, store). The engine checks alone are
tools/bench_checks.py.

    python tools/bench_desk.py [N ...]      default 100 1000
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import yaml  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat  # noqa: E402

import bench_checks  # noqa: E402
from keyclerk import config  # noqa: E402


def timed(f):
    t = time.perf_counter()
    out = f()
    return time.perf_counter() - t, out


def measure(n: int) -> dict:
    from keyclerk.desk import Desk, Store
    tmp = Path(tempfile.mkdtemp())
    seed = tmp / "records.yaml"
    seed.write_text(yaml.safe_dump(bench_checks.organisation(n), sort_keys=False), encoding="utf-8")
    key = tmp / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    start, desk = timed(lambda: Desk(Store(tmp / "store", key, seed)))
    first, doc = timed(desk.store.load)
    again, _ = timed(desk.store.load)
    ann = {"anchor": "idp:7c1f-ann", "roles": []}
    body = {"action": "add_member", "group": "finance", "anchor": "idp:91d0-bert", "days": 30}
    preview, _ = timed(lambda: desk.preview(ann, body))
    change, out = timed(lambda: desk.propose(ann, body))
    return {"people": n, "desk start": start, "first load": first, "load": again, "preview": preview,
            "change": change, "outcome": out.get("outcome"), "reasons": (out.get("reasons") or [])[:1]}


def main(argv: list[str]) -> int:
    config.configure(bench_checks.bench_config())
    for n in [int(a) for a in argv if a.isdigit()] or [100, 1000]:
        r = measure(n)
        print(f"{r['people']:6d} people: start {r['desk start']:.2f} s, first load {r['first load']:.2f} s, "
              f"load {r['load']:.3f} s, preview {r['preview']:.2f} s, change {r['change']:.2f} s "
              f"({r['outcome']} {r['reasons']})")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
