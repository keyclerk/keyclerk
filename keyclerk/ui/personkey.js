// SPDX-License-Identifier: EUPL-1.2
// KeyClerk person keys in the browser (decision 0014 points 7 and 8): the X25519 key a passkey derives through
// WebAuthn PRF, and opening a kc-relay-v1 envelope with it. Mirrors keyclerk/relay.py exactly; tests run both on the
// same vectors. The private key exists only while it is used: derived from the PRF output, never stored.
"use strict";

const PK = (() => {
  const enc = new TextEncoder();
  const PRF_SALT = enc.encode("keyclerk person key prf v1");      // what the authenticator's PRF is evaluated on
  const PERSON_INFO = enc.encode("kc-person-key-v1");
  // PKCS#8 wrapping of a raw X25519 private key (RFC 8410): WebCrypto imports X25519 private keys only this way
  const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

  const b64e = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64d = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
  const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };

  async function hkdf(ikm, salt, info, bytes) {
    const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, bytes * 8));
  }

  // The person key from a PRF output: (private CryptoKey, public raw bytes)
  async function fromPrf(prf) {
    const seed = await hkdf(new Uint8Array(prf), new Uint8Array(0), PERSON_INFO, 32);
    const priv = await crypto.subtle.importKey("pkcs8", cat(PKCS8_PREFIX, seed), { name: "X25519" }, true, ["deriveBits"]);
    const jwk = await crypto.subtle.exportKey("jwk", priv);
    seed.fill(0);
    return { priv, pub: b64d(jwk.x) };
  }

  // Open an envelope sent to this key; the context is bound as associated data
  async function open(priv, pub, env) {
    if (!env || env.format !== "kc-relay-v1") throw new Error("not a kc-relay-v1 envelope");
    const epk = b64d(env.epk);
    const peer = await crypto.subtle.importKey("raw", epk, { name: "X25519" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer }, priv, 256));
    const key = await hkdf(shared, cat(epk, pub), enc.encode("kc-relay-v1|" + env.context), 32);
    const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(env.nonce), additionalData: enc.encode(env.context) }, k, b64d(env.ct));
    shared.fill(0); key.fill(0);
    return new Uint8Array(plain);
  }

  // Register a hardware key on this desk: a passkey with PRF, user verification required. Returns what to register.
  async function register(name) {
    if (!window.PublicKeyCredential) throw new Error("this browser has no passkeys (WebAuthn)");
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { name: "KeyClerk desk", id: location.hostname },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "direct",
      extensions: { prf: { eval: { first: PRF_SALT } } } } });
    const ext = cred.getClientExtensionResults().prf || {};
    if (!ext.enabled && !(ext.results && ext.results.first)) throw new Error("this key does not offer PRF (hmac-secret): it cannot receive lease secrets, and there is no fallback");
    const prf = ext.results && ext.results.first ? ext.results.first : await evaluate(cred.rawId);
    const { pub } = await fromPrf(prf);
    const flags = new Uint8Array(cred.response.getAuthenticatorData ? cred.response.getAuthenticatorData() : new ArrayBuffer(37))[32];
    return { public_key: b64e(pub), credential_id: b64e(cred.rawId), user_verification: Boolean(flags & 0x04),
      attestation: (cred.response.attestationObject ? "present" : "none") };
  }

  // The PRF output for a registered credential: one touch and the PIN or biometric
  async function evaluate(credentialId) {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname, userVerification: "required",
      allowCredentials: [{ type: "public-key", id: typeof credentialId === "string" ? b64d(credentialId) : credentialId }],
      extensions: { prf: { eval: { first: PRF_SALT } } } } });
    const r = (a.getClientExtensionResults().prf || {}).results;
    if (!r || !r.first) throw new Error("the key gave no PRF output");
    return r.first;
  }

  // Decrypt a taken envelope: the passkey derives the key again; it is checked against the registered public key
  async function openWithKey(credentialId, registeredPublic, env) {
    const { priv, pub } = await fromPrf(await evaluate(credentialId));
    if (b64e(pub) !== registeredPublic) throw new Error("this key derives a different person key than the one registered");
    return open(priv, pub, env);
  }

  return { fromPrf, open, register, evaluate, openWithKey, b64e, b64d };
})();
if (typeof module !== "undefined") module.exports = PK;
