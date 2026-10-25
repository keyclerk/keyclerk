# 0016: An assured edge proves its TPM, its attestation key and its boot state

- Status: accepted (2026-10-23, the maintainer's choices: officer pin plus vendor chain; a quote on every pull; PCR 7
  by default)
- Date: 2026-10-23
- Closes the open point of 0014a (the hardware profile was a claim) and gives the edge's trust model its input:
  hardware facts reach the policy from attestation, never from configuration.

## Decision
1. **The TPM is genuine: officer pin and vendor chain.** At enrolment the officer reads the endorsement key's (EK)
   fingerprint on site (SHA-256 over its SubjectPublicKeyInfo) and the signed enrolment statement carries it. Where the
   TPM carries an EK certificate, it must also name that key and chain to a manufacturer root the deployment lists
   (configuration: `edges.ek_roots`, `edges.ek_intermediates`). A TPM without a certificate rests on the officer's pin
   alone, and the policy sees `ek_certified: false`.
2. **The attestation key (AK) lives in that TPM: credential activation.** The edge registers an AK, a restricted
   signing key fixed to its TPM. KeyClerk encrypts a challenge to the EK, bound to the AK's name (TPM2_MakeCredential,
   in software); the edge recovers it with TPM2_ActivateCredential and returns it. Until it does, the edge is not
   attested and gets what a basic edge gets.
3. **Fresh state on every pull.** Every bundle pull of an assured edge carries a quote by the AK over
   `sha256("kc-edge-quote-v1|edge|seconds|nonce")`, the values of its signed request, so a quote is never older than
   the request and never replayable (the desk refuses a nonce twice). No good quote, no new assured bundle: a TPM fault
   fails closed into an outage of offline grants, never into trust.
4. **PCR 7 by default.** The default policy requires the Secure Boot state (PCR 7) the officer recorded at enrolment.
   Deployments add PCRs 0 to 6 or a kernel baseline in Rego. A changed PCR 7 refuses the assured bundle and raises an
   incident; a new baseline is an officer-signed change, like a ceiling.

## Verified
- `keyclerk.attest` is checked against vectors from a software TPM (swtpm and tpm2-tools, `tests/fixtures/tpm/make.sh`):
  the AK name, both quotes (one after PCR 7 changed), the EK certificate chain, and refusals for a wrong nonce, PCR
  values, signature, key, pin, root and validity.
- The software MakeCredential is activated by a TPM for the AK's name and refused for any other name
  (`tests/fixtures/tpm/roundtrip.sh`).

## Not covered
- PCR 7 does not say which kernel booted: a validly signed but vulnerable boot chain passes the default.
- A TPM's EK certificate proves the chip's make, not that this chip sits in this box; the officer's pin on site is what
  ties the two.
- swtpm's local CA stands in for a manufacturer root in tests; real roots are the deployment's list.
