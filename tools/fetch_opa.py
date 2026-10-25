# SPDX-License-Identifier: EUPL-1.2
"""Install the pinned OPA binary for CI: a fixed release, verified against its sha256 before it is used (the policy
tests run with it; the engine itself evaluates compiled WebAssembly and needs no OPA at run time).
Usage: python tools/fetch_opa.py [--dest /usr/local/bin/opa]
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import urllib.request

VERSION = "v1.21.1"
URL = f"https://github.com/open-policy-agent/opa/releases/download/{VERSION}/opa_linux_amd64_static"
SHA256 = "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"


def fetch(dest: str) -> None:
    with urllib.request.urlopen(URL, timeout=120) as r:
        blob = r.read()
    got = hashlib.sha256(blob).hexdigest()
    if got != SHA256:
        sys.exit(f"ERROR opa {VERSION}: sha256 {got} does not match the pin {SHA256}")
    with open(dest, "wb") as f:
        f.write(blob)
    os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"opa {VERSION} installed at {dest} (sha256 verified)")


if __name__ == "__main__":
    fetch(sys.argv[sys.argv.index("--dest") + 1] if "--dest" in sys.argv else "/usr/local/bin/opa")
