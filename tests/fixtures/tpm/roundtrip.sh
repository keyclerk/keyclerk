#!/bin/sh
# Credential activation round trip: keyclerk.attest.make_credential in software, TPM2_ActivateCredential in swtpm.
set -e
apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0 xxd python3-cryptography >/dev/null 2>&1
mkdir -p /tpm /w && cd /w
swtpm_setup --tpm2 --tpmstate /tpm --create-ek-cert --lock-nvram --overwrite >/dev/null 2>&1
swtpm socket --tpm2 --tpmstate dir=/tpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_createek -c ek.ctx -G rsa -u ek.tss -f tss
tpm2_flushcontext -t; tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.tss -f tss -n ak.name >/dev/null
tpm2_flushcontext -t
for case in good wrongname; do
  PYTHONPATH=/src python3 - "$case" <<'PY'
import sys
from keyclerk import attest as A
ek = A.parse_public(open("ek.tss", "rb").read())
name = open("ak.name", "rb").read()
if sys.argv[1] == "wrongname":
    name = name[:2] + bytes(32)
idobj, encsec = A.make_credential(ek, name, b"keyclerk-challenge-0123456789abc")
open("cred.bin", "wb").write(A.credential_file(idobj, encsec))
PY
  tpm2_flushcontext -t; tpm2_flushcontext -s
  tpm2_startauthsession --policy-session -S s.ctx
  tpm2_policysecret -S s.ctx -c e >/dev/null
  if tpm2_activatecredential -c ak.ctx -C ek.ctx -i cred.bin -o got.bin -P "session:s.ctx" >/dev/null 2>&1 && [ "$(cat got.bin)" = "keyclerk-challenge-0123456789abc" ]; then
    echo "$case: activated"
  else
    echo "$case: refused by the TPM"
  fi
  tpm2_flushcontext s.ctx 2>/dev/null || true
done
