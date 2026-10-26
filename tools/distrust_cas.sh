#!/bin/sh
# SPDX-License-Identifier: EUPL-1.2
# Take out of a Debian image's trust store the root certificates that certifi 2026.10.19 dropped after the eMudhra
# key incident (2026-10-20: eight intermediates with trivially weak private keys): emSign ECC Root CA - G3, emSign Root
# CA - C1 and emSign ECC Root CA - C3. emSign Root CA - G1 stays, as in certifi. Python's ssl and every other TLS client
# in the image read this store. Remove this step once the base image ships ca-certificates and a Python that reject
# them (Python 3.12.16 does), and tests/test_trust_store.py with it.
# Usage (as root, in the image): sh tools/distrust_cas.sh
set -eu
conf=/etc/ca-certificates.conf
[ -f "$conf" ] || { echo "distrust_cas: no $conf (not a Debian image): nothing to do" >&2; exit 0; }
for name in emSign_ECC_Root_CA_-_G3 emSign_Root_CA_-_C1 emSign_ECC_Root_CA_-_C3; do
    sed -i "s|^mozilla/$name\.crt\$|!mozilla/$name.crt|" "$conf"
done
update-ca-certificates --fresh > /dev/null 2>&1
