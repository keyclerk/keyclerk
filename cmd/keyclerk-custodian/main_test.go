// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

func newCustodian(t testing.TB) *Custodian {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	st := &State{Format: stateFormat, Realm: "example", Origin: "keyclerk.example/log-1",
		Origins: []string{"keyclerk.example/log-1"}, Key: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		Retired: []Retired{}, Fence: 1, Frontier: []node{}}
	if err := save(dir, st, key); err != nil {
		t.Fatal(err)
	}
	return &Custodian{dir: dir, key: key, st: st}
}

// link is a link body in the canonical bytes every verifier accepts.
func link(seq int64, prev, at string) []byte {
	body := map[string]any{"format": linkLabel, "realm": "example", "seq": seq, "prev": prev, "fence": int64(1),
		"at": at, "change": map[string]any{"ops": []any{}, "entry": map[string]any{}}}
	var buf bytes.Buffer
	_ = encodeCanonical(&buf, body)
	return append([]byte(linkLabel+"\n"), buf.Bytes()...)
}

// Decision 0033 point 3 (the Horcrux race): requests for one position, at once, give one signature over one body.
func TestOnePositionOneSignatureUnderConcurrency(t *testing.T) {
	c := newCustodian(t)
	var wg sync.WaitGroup
	sigs := make([]string, 64)
	errs := make([]error, 64)
	for i := range sigs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			at := "2026-11-07T12:00:00Z"
			if i%2 == 1 { // half of them ask for another body at the same position
				at = fmt.Sprintf("2026-11-07T12:00:%02dZ", 1+i%58)
			}
			s, err := c.Sign(link(0, zero, at))
			sigs[i], errs[i] = hex.EncodeToString(s), err
		}(i)
	}
	wg.Wait()
	signed := map[string]bool{}
	for i := range sigs {
		if errs[i] == nil {
			signed[sigs[i]] = true
		}
	}
	if len(signed) != 1 {
		t.Fatalf("%d different signatures at position 0, want exactly one", len(signed))
	}
	if c.st.Size != 1 {
		t.Fatalf("size %d after one position, want 1", c.st.Size)
	}
}

func TestTheStateOnDiskIsWrittenBeforeTheAnswer(t *testing.T) {
	c := newCustodian(t)
	if _, err := c.Sign(link(0, zero, "2026-11-07T12:00:00Z")); err != nil {
		t.Fatal(err)
	}
	got, err := load(c.dir, c.key)
	if err != nil || got.Size != 1 || got.Head != c.st.Head {
		t.Fatalf("the state on disk is %+v, %v; the custodian answered at size 1", got, err)
	}
}

// The request parser never panics, whatever arrives on the socket (decision 0033 point 9).
func FuzzAnswer(f *testing.F) {
	f.Add([]byte(`{"op":"sign","data":"a2MtY2hhbmdlLWxpbmstdjEKe30="}`))
	f.Add([]byte(`{"op":"state"}`))
	f.Add([]byte(`{"op":"sign","data":"MTIzCjQ1Ngp4eHgK"}`))
	f.Add([]byte(`{"op":"follow_begin","mode":"rebuild","note":"x"}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		c := newCustodian(t)
		c.witnessVkey = "w+00000000+BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		_ = c.answer(line, 1)
	})
}
