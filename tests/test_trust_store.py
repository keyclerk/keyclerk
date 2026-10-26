# SPDX-License-Identifier: EUPL-1.2
"""The image's TLS trust leaves out the emSign roots certifi dropped after the eMudhra key incident (2026-10-20);
tools/distrust_cas.sh takes them out. Checked where that script applies: a Debian image, as in CI and the Containerfile."""
import os
import ssl

import pytest

DROPPED = {"emSign ECC Root CA - G3", "emSign Root CA - C1", "emSign ECC Root CA - C3"}


@pytest.mark.skipif(not os.path.exists("/etc/ca-certificates.conf"), reason="not a Debian image")
def test_python_trusts_none_of_the_dropped_emsign_roots():
    ctx = ssl.create_default_context()
    names = {v for cert in ctx.get_ca_certs() for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"}
    assert not DROPPED & names, f"run tools/distrust_cas.sh in the image: still trusted {sorted(DROPPED & names)}"
