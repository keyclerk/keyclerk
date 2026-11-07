// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The conformance vectors (decision 0033 point 9), written by tools/gen_custodian_conformance.py from the Python
// reference: every step signed with exactly the reference's signature, or refused for the same reason.
func TestConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/conformance/custodian.json")
	if err != nil {
		t.Skip("the vectors live in the repository's tests/conformance")
	}
	var v struct {
		Realm, Origin, Seed, Public string
		Steps                       []struct {
			Name, Data, Signature, Refused string
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != v.Public {
		t.Fatal("the vectors' seed is not their public key")
	}
	dir := t.TempDir()
	st := &State{Format: stateFormat, Realm: v.Realm, Origin: v.Origin, Origins: []string{v.Origin}, Key: v.Public,
		Retired: []Retired{}, Fence: 1, Frontier: []node{}}
	if err := save(dir, st, key); err != nil {
		t.Fatal(err)
	}
	c := &Custodian{dir: dir, key: key, st: st}
	for _, s := range v.Steps {
		data, _ := base64.StdEncoding.DecodeString(s.Data)
		sig, err := c.Sign(data)
		switch {
		case s.Refused != "" && err == nil:
			t.Errorf("%s: signed, want refused (%s)", s.Name, s.Refused)
		case s.Refused != "" && !strings.Contains(err.Error(), s.Refused):
			t.Errorf("%s: refused with %q, want %q", s.Name, err, s.Refused)
		case s.Refused == "" && err != nil:
			t.Errorf("%s: refused (%v), want signed", s.Name, err)
		case s.Refused == "" && hex.EncodeToString(sig) != s.Signature:
			t.Errorf("%s: another signature than the reference's", s.Name)
		}
	}
}
