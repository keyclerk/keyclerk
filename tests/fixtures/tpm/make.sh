#!/bin/sh
set -e
apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0 xxd openssl >/dev/null 2>&1
mkdir -p /tpm /out
swtpm_setup --tpm2 --tpmstate /tpm --create-ek-cert --create-platform-cert --lock-nvram --overwrite >/out/setup.log 2>&1 || echo "setup without certs" >>/out/setup.log
swtpm socket --tpm2 --tpmstate dir=/tpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
cd /out
tpm2_nvread 0x1c00002 -o ek-cert.der 2>/dev/null || echo "no ek cert" > ek-cert.missing
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_createek -c ek.ctx -G rsa -u ek.pub -f pem
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pub -n ak.name -f pem
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_readpublic -c ak.ctx -o ak.tpmt -f tss >/dev/null
printf 'challenge-secret-0123456789abcdef' > secret.bin
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_makecredential -T none -e ek.pub -s secret.bin -n $(xxd -p -c 256 ak.name) -o cred.bin -G rsa
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_startauthsession --policy-session -S s.ctx
tpm2_policysecret -S s.ctx -c e
tpm2_activatecredential -c ak.ctx -C ek.ctx -i cred.bin -o recovered.bin -P "session:s.ctx"
tpm2_flushcontext s.ctx
cmp secret.bin recovered.bin && echo activation-ok
printf 'nonce-from-keyclerk-0001' > nonce.bin
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_quote -c ak.ctx -l sha256:0,7 -q $(xxd -p -c 256 nonce.bin) -m quote.msg -s quote.sig -o quote.pcrs -F values -g sha256
tpm2_checkquote -l sha256:0,7 -u ak.pub -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q $(xxd -p -c 256 nonce.bin) && echo checkquote-ok
tpm2_pcrread sha256:0,7 -o pcrs.bin > pcrs.yaml
# quotes bound to an edge request (keyclerk.attest.quote_nonce): edge plant-a, 2026-10-24T08:00Z, two request nonces
printf 'kc-edge-quote-v1|plant-a|1792828800|reqnonce000000000001' | sha256sum | cut -c1-64 > bound1.hex
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_quote -c ak.ctx -l sha256:7 -q $(cat bound1.hex) -m bound1.msg -s bound1.sig -o bound1.pcrs -F values -g sha256
tpm2_pcrextend 7:sha256=$(printf 'secure-boot-db-changed' | sha256sum | cut -c1-64)
printf 'nonce-from-keyclerk-0002' > nonce2.bin
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_quote -c ak.ctx -l sha256:0,7 -q $(xxd -p -c 256 nonce2.bin) -m quote2.msg -s quote2.sig -o quote2.pcrs -F values -g sha256
printf 'kc-edge-quote-v1|plant-a|1792828800|reqnonce000000000002' | sha256sum | cut -c1-64 > bound2.hex
tpm2_flushcontext -t; tpm2_flushcontext -s; tpm2_quote -c ak.ctx -l sha256:7 -q $(cat bound2.hex) -m bound2.msg -s bound2.sig -o bound2.pcrs -F values -g sha256
tpm2_checkquote -l sha256:0,7 -u ak.pub -m quote2.msg -s quote2.sig -f quote2.pcrs -g sha256 -q $(xxd -p -c 256 nonce2.bin) && echo checkquote2-ok
cp /var/lib/swtpm-localca/*.pem /out/ 2>/dev/null || find / -name "swtpm-localca*" -o -name "issuercert.pem" 2>/dev/null | head; rm -f /out/signkey.pem /out/swtpm-localca-rootca-privkey.pem /out/*.ctx /out/recovered.bin; ls /out
