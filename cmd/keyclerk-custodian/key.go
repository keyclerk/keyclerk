// SPDX-License-Identifier: EUPL-1.2

// Where the key lives (decision 0033 point 6): a file of the custodian's own user; that file sealed by the TPM to the
// machine's boot state; or, in the separate PKCS#11 build, a token holding an Ed25519 key (CKM_EDDSA). The rest of the
// custodian sees a crypto.Signer either way.
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// macKey is the state seal's key. A file key's comes from its seed (as states written before PKCS#11 have it); a key
// that never shows its seed gives its deterministic Ed25519 signature over a fixed label, which only its holder makes.
func macKey(key crypto.Signer) []byte {
	if k, ok := key.(ed25519.PrivateKey); ok {
		h := sha256.Sum256(append([]byte("kc-custodian-state-mac\n"), k.Seed()...))
		return h[:]
	}
	sig, err := key.Sign(nil, []byte("kc-custodian-state-mac-v1"), crypto.Hash(0))
	if err != nil {
		panic("the key does not sign: " + err.Error()) // checked at start (checkKey), so never reached in service
	}
	h := sha256.Sum256(append([]byte("kc-custodian-state-mac\n"), sig...))
	return h[:]
}

func sign(key crypto.Signer, data []byte) ([]byte, error) {
	return key.Sign(nil, data, crypto.Hash(0))
}

func pubHex(key crypto.Signer) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// checkKey proves at start that the key signs Ed25519 under its public key, and deterministically (an HSM's EdDSA, or a
// module that answers otherwise, is caught before anything is signed).
func checkKey(key crypto.Signer) error {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return errors.New("the key is not an Ed25519 key")
	}
	msg := []byte("kc-custodian-key-check-v1")
	a, err := sign(key, msg)
	if err != nil {
		return err
	}
	b, err := sign(key, msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, a) || string(a) != string(b) {
		return errors.New("the key's signatures are not Ed25519 under its public key, or not deterministic: refused")
	}
	return nil
}

// readKey reads a key file: 64 hex digits, or with tpmSpec set the TPM-sealed file (kc-custodian-tpm-key-v1).
func readKey(path, tpmSpec string) (crypto.Signer, error) {
	if err := keyPerms(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if s, ok := readSealed(raw); ok {
		if tpmSpec == "" {
			return nil, errors.New("the key file is sealed by a TPM: start with --tpm")
		}
		t, err := openTPM(tpmSpec)
		if err != nil {
			return nil, err
		}
		defer t.Close()
		return unsealKey(t, s)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the key file is not an Ed25519 private key (64 hex digits) or a TPM-sealed key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
