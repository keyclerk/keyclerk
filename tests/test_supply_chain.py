# SPDX-License-Identifier: EUPL-1.2
"""The image installs only hash-locked dependencies, and the lock agrees with the constraints."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", re.M)


def _pins(text):
    return {m.group(1).lower().replace("_", "-"): m.group(2) for m in PIN.finditer(text)}


def test_every_constraint_is_locked_with_its_version_and_hashes():
    cons = _pins((ROOT / "constraints.txt").read_text(encoding="utf-8"))
    lock_text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    lock = _pins(lock_text)
    assert cons and all(lock.get(k.lower()) == v for k, v in cons.items()), {k: (v, lock.get(k)) for k, v in cons.items()}
    blocks = re.split(r"\n(?=[A-Za-z])", lock_text)
    assert all("--hash=sha256:" in b for b in blocks if PIN.match(b))


def test_every_runtime_dependency_is_constrained():
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    cons = _pins((ROOT / "constraints.txt").read_text(encoding="utf-8"))
    for d in deps:
        name = re.split(r"[<>=!~ ]", d, maxsplit=1)[0].lower()
        assert name in cons, name


def test_the_image_installs_with_hashes_only():
    cf = (ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "--require-hashes" in cf and "--only-binary=:all:" in cf and "pip install --no-cache-dir ." not in cf
    assert re.search(r"^FROM \S+@sha256:[0-9a-f]{64}$", cf, re.M)


def test_vendored_browser_code_is_the_file_its_record_names():
    """The desk serves its own copy of third-party browser code (the CSP allows only 'self'); each file matches the
    digest recorded when it was taken from the registry, with the registry's integrity value beside it."""
    import hashlib
    import json
    vendor = ROOT / "keyclerk" / "ui" / "vendor"
    rec = json.loads((vendor / "vendor.json").read_text(encoding="utf-8"))
    assert rec
    for name, r in rec.items():
        assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == r["sha256"], name
        assert r["licence"] and r["npm_integrity"].startswith("sha512-")
