// SPDX-License-Identifier: EUPL-1.2

//go:build pkcs11

package main

// The PKCS#11 build against a token: KC_P11_CONFIG names its {module, token, key, pin_file} (SoftHSM 2 with an
// Ed25519 key made by pkcs11-tool --keypairgen --key-type EC:edwards25519); without it this skips.

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

func TestAKeyInATokenSignsLinksAndSealsTheState(t *testing.T) {
	cfg := os.Getenv("KC_P11_CONFIG")
	if cfg == "" {
		t.Skip("no token (KC_P11_CONFIG)")
	}
	k, err := openPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, plain := k.(ed25519.PrivateKey); plain {
		t.Fatal("the key is not the token's")
	}
	if err := checkKey(k); err != nil {
		t.Fatal(err)
	}
	if m := macKey(k); !bytes.Equal(m, macKey(k)) || bytes.Equal(m, make([]byte, 32)) {
		t.Fatal("the state seal's key is not stable")
	}
	dir := t.TempDir()
	st := &State{Format: stateFormat, Realm: "example", Origin: "keyclerk.example/log-1",
		Origins: []string{"keyclerk.example/log-1"}, Key: pubHex(k), Retired: []Retired{}, Fence: 1, Frontier: []node{}}
	if err := save(dir, st, k); err != nil {
		t.Fatal(err)
	}
	c := &Custodian{dir: dir, key: k, st: st}
	data := link(0, zero, "2026-11-07T10:00:00Z")
	sig, err := c.Sign(data)
	if err != nil || !ed25519.Verify(k.Public().(ed25519.PublicKey), data, sig) {
		t.Fatalf("the token's link signature: %v", err)
	}
	chain(t, c, 2, "2026-11-07T10:00:01Z")
	back, err := load(dir, k)
	if err != nil || back.Size != 3 {
		t.Fatalf("the state sealed under the token's key: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := load(dir, other); err == nil {
		t.Fatal("the state opened under another key")
	}
}
