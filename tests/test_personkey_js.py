# SPDX-License-Identifier: EUPL-1.2
"""The browser's person key and envelope (keyclerk/ui/personkey.js) agree with keyclerk/relay.py on the same vectors:
the same public key from a PRF output, and the browser opens what Python sealed. Needs Node 20 or later (WebCrypto
X25519); skipped where Node is absent."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from keyclerk import relay as R

ROOT = Path(__file__).resolve().parent.parent
HARNESS = """
global.atob = s => Buffer.from(s, "base64").toString("binary");
global.btoa = s => Buffer.from(s, "binary").toString("base64");
const PK = require(process.argv[1]);
const v = JSON.parse(process.argv[2]);
(async () => {
  const { priv, pub } = await PK.fromPrf(PK.b64d(v.prf));
  const plain = await PK.open(priv, pub, v.env);
  process.stdout.write(JSON.stringify({ pub: PK.b64e(pub), plain: Buffer.from(plain).toString() }));
})().catch(e => { process.stderr.write(String(e)); process.exit(1); });
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed here")
def test_the_browser_derives_the_same_key_and_opens_what_python_sealed():
    prf = bytes(range(7, 39))
    _, pub = R.person_key_from_prf(prf)
    env = R.encrypt(R.b64e(pub), "a lease secret, 8 bytes or more".encode(), "lease:L-42")
    out = subprocess.run(["node", "-e", HARNESS, str(ROOT / "keyclerk" / "ui" / "personkey.js"),
                          json.dumps({"prf": R.b64e(prf), "env": env})], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got["pub"] == R.b64e(pub) and got["plain"] == "a lease secret, 8 bytes or more"
