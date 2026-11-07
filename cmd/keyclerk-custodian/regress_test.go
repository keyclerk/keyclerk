// SPDX-License-Identifier: EUPL-1.2

package main

// The 2026-11-07 review's attacks on the custodian, each now refused: the fork through a follow (A2, A3, A4, dos-1),
// signing what it does not recognise (A1, fuzz-1), bytes no verifier accepts (diff-1 to diff-4, A11, A12), a retired
// key at any position (A13), one snapshot per size (A8), a changed or carried-in state (dos-2, A6, fuzz-3), a retired
// exporter (A5).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type witnessKey struct {
	name string
	key  ed25519.PrivateKey
}

func newWitness() witnessKey {
	_, k, _ := ed25519.GenerateKey(nil)
	return witnessKey{"witness.example/commit", k}
}

func (w witnessKey) vkey() string {
	raw := append([]byte{0x04}, w.key.Public().(ed25519.PublicKey)...)
	id := sha256.Sum256(append([]byte(w.name+"\n"), raw...))
	return w.name + "+" + hex.EncodeToString(id[:4]) + "+" + base64.StdEncoding.EncodeToString(raw)
}

func (w witnessKey) note(origin string, size int64, root []byte) string {
	text := origin + "\n" + strconv.FormatInt(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root) + "\n"
	raw := append([]byte{0x04}, w.key.Public().(ed25519.PublicKey)...)
	id := sha256.Sum256(append([]byte(w.name+"\n"), raw...))
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, 1_800_000_000)
	sig := ed25519.Sign(w.key, []byte("cosignature/v1\ntime 1800000000\n"+text))
	line := "— " + w.name + " " + base64.StdEncoding.EncodeToString(append(append(id[:4], t...), sig...))
	return text + "\n" + line + "\n"
}

// chain signs n links on c from its current size and returns them sealed.
func chain(t *testing.T, c *Custodian, n int, at string) []sealedLink {
	t.Helper()
	var out []sealedLink
	for i := 0; i < n; i++ {
		prev := zero
		if c.st.Size > 0 {
			prev = c.st.Head
		}
		data := link(c.st.Size, prev, at)
		sig, err := c.Sign(data)
		if err != nil {
			t.Fatalf("link %d: %v", c.st.Size, err)
		}
		out = append(out, sealedLink{base64.StdEncoding.EncodeToString(data[len(linkLabel)+1:]), hex.EncodeToString(sig)})
	}
	return out
}

func follow3(c *Custodian, owner uint64, mode, note string, links []sealedLink) map[string]any {
	req, _ := json.Marshal(map[string]any{"op": "follow_begin", "mode": mode, "note": note})
	if out := c.answer(req, owner); out["refused"] != nil {
		return out
	}
	req, _ = json.Marshal(map[string]any{"op": "follow_links", "links": links})
	if out := c.answer(req, owner); out["refused"] != nil {
		return out
	}
	return c.answer([]byte(`{"op":"follow_end"}`), owner)
}

func refusedWith(t *testing.T, out map[string]any, want string) {
	t.Helper()
	r, _ := out["refused"].(string)
	if r == "" || !strings.Contains(r, want) {
		t.Fatalf("want a refusal with %q, got %v", want, out)
	}
}

func signRefused(t *testing.T, c *Custodian, data []byte, want string) {
	t.Helper()
	if _, err := c.Sign(data); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal with %q, got %v", want, err)
	}
}

// A2, A4, dos-1: a custodian never goes below its own size, so it never signs a position twice.
func TestAFollowNeverRollsTheCustodianBackOrReSignsAPosition(t *testing.T) {
	a, b := newCustodian(t), newCustodian(t)
	b.key, b.st.Key = a.key, a.st.Key
	w := newWitness()
	a.witnessVkey, b.witnessVkey = w.vkey(), w.vkey()
	_ = save(b.dir, b.st, b.key)
	links := chain(t, a, 4, "2026-11-07T12:00:00Z")
	if out := follow3(b, 1, "extend", w.note(a.st.Origin, 4, a.st.root()), links); out["refused"] != nil {
		t.Fatalf("an honest follow: %v", out)
	}
	chain(t, b, 1, "2026-11-07T13:00:00Z") // b's own position 4
	old := w.note(a.st.Origin, 2, func() []byte { s := newCustodian(t); _ = s; return make([]byte, 32) }())
	refusedWith(t, follow3(b, 1, "rebuild", old, links[:2]), "never below the floor")
	refusedWith(t, follow3(b, 1, "rebuild", w.note(a.st.Origin, 4, a.st.root()), links), "never signs a position twice")
}

// dos-1: nothing is signed while a follow is under way, and a follow over a moved state changes nothing.
func TestNothingIsSignedDuringAFollow(t *testing.T) {
	c := newCustodian(t)
	w := newWitness()
	c.witnessVkey = w.vkey()
	req, _ := json.Marshal(map[string]any{"op": "follow_begin", "mode": "extend", "note": w.note(c.st.Origin, 1,
		make([]byte, 32))})
	if out := c.answer(req, 7); out["refused"] != nil {
		t.Fatal(out)
	}
	signRefused(t, c, link(0, zero, "2026-11-07T12:00:00Z"), "a follow is under way")
	refusedWith(t, c.answer(req, 8), "another connection's follow")
	c.dropFollow(7)
	if _, err := c.Sign(link(0, zero, "2026-11-07T12:00:00Z")); err != nil {
		t.Fatalf("after the follow's connection went: %v", err)
	}
}

// A3: links that stop short of the witness's tree, or a note of another log, are not followed.
func TestAFollowLandsExactlyOnTheWitnessTree(t *testing.T) {
	a, b := newCustodian(t), newCustodian(t)
	b.key, b.st.Key = a.key, a.st.Key
	_ = save(b.dir, b.st, b.key)
	w := newWitness()
	b.witnessVkey = w.vkey()
	links := chain(t, a, 3, "2026-11-07T12:00:00Z")
	refusedWith(t, follow3(b, 1, "extend", w.note(a.st.Origin, 4, make([]byte, 32)), links), "not the tree")
	refusedWith(t, follow3(b, 1, "extend", w.note("another.example/log", 3, a.st.root()), links), "not one of this log's")
}

// A1, fuzz-1, A11, diff-4: nothing unrecognised is signed; a checkpoint text is strict or refused.
func TestNothingFallsThroughToASignature(t *testing.T) {
	c := newCustodian(t)
	chain(t, c, 1, "2026-11-07T12:00:00Z")
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	o := c.st.Origin
	for _, bad := range []string{
		o + "\n01\n" + root + "\n",                  // a leading zero
		o + "\n+1\n" + root + "\n",                  // a sign
		o + "\n9223372036854775808\n" + root + "\n", // past int64
		o + "\n1\n" + root + "\nextension\n",        // an extension line
		"x+y\n1\n" + root + "\n",                    // a name with a plus
		"records:\n  realm: example\n",              // a YAML revision
		"anything at all",
	} {
		if _, err := c.Sign([]byte(bad)); err == nil {
			t.Fatalf("signed %q", bad)
		}
	}
}

// diff-1, diff-2, A12, fuzz-2: a link body is canonical, its numbers below 2^53.
func TestALinkBodyIsCanonical(t *testing.T) {
	c := newCustodian(t)
	good := link(0, zero, "2026-11-07T12:00:00Z")
	raw := string(good[len(linkLabel)+1:])
	for _, bad := range []string{
		strings.Replace(raw, `"at"`, ` "at"`, 1), // a space
		raw + "\n",                               // trailing bytes
		strings.Replace(raw, `"fence":1`, `"fence":1,"fence":1`, 1),                   // a duplicate key
		strings.Replace(raw, `"realm":"example"`, `"realm":"`+"\\"+`u0065xample"`, 1), // an escape
		strings.Replace(raw, `"fence":1`, `"fence":9007199254740992`, 1),              // 2^53
		strings.Replace(raw, `"fence":1`, `"fence":1.0`, 1),                           // a float
	} {
		signRefused(t, c, []byte(linkLabel+"\n"+bad), "")
	}
	if _, err := c.Sign(good); err != nil {
		t.Fatalf("the canonical body: %v", err)
	}
}

// diff-3, A8: statements carry exactly their fields, and one snapshot per size.
func TestStatementsCarryExactlyTheirFields(t *testing.T) {
	c := newCustodian(t)
	chain(t, c, 1, "2026-11-07T12:00:00Z")
	root, head := hex.EncodeToString(c.st.root()), c.st.Head
	enc := func(v map[string]any) []byte {
		var b bytes.Buffer
		_ = encodeCanonical(&b, v)
		return b.Bytes()
	}
	cp := map[string]any{"format": cpLabel, "realm": "example", "size": int64(1), "root": root, "head": head,
		"fence": int64(1), "at": "2026-11-07T12:00:00Z"}
	short := map[string]any{"format": cpLabel, "realm": "example", "size": int64(1), "root": root, "head": head}
	signRefused(t, c, append([]byte(cpLabel+"\n"), enc(short)...), "not a kc-checkpoint-v1 body")
	if _, err := c.Sign(append([]byte(cpLabel+"\n"), enc(cp)...)); err != nil {
		t.Fatal(err)
	}
	snap := func(sha string) []byte {
		return append([]byte(snapLabel+"\n"), enc(map[string]any{"format": snapLabel, "realm": "example",
			"size": int64(1), "root": root, "head": head, "fence": int64(1), "at": "2026-11-07T12:00:00Z",
			"parts": int64(0), "migration": nil, "restore": nil,
			"state": map[string]any{"sha256": sha, "bytes": int64(1), "records": int64(1)}})...)
	}
	if _, err := c.Sign(snap(strings.Repeat("a", 64))); err != nil {
		t.Fatal(err)
	}
	signRefused(t, c, snap(strings.Repeat("b", 64)), "one per size")
}

// A13: a retired key's link is taken only before the position it stopped at.
func TestARetiredKeyOnlyBeforeItsSwitch(t *testing.T) {
	old := newCustodian(t)
	links := chain(t, old, 3, "2026-11-07T12:00:00Z")
	st := old.st.clone()
	_, nk, _ := ed25519.GenerateKey(nil)
	st.Size, st.Head, st.Fence, st.Frontier, st.LastBody, st.LastSig = 0, "", 1, []node{}, "", ""
	st.Retired = []Retired{{Key: old.st.Key, Until: 2}}
	st.Key = hex.EncodeToString(nk.Public().(ed25519.PublicKey))
	for _, l := range links[:2] {
		if err := take(st, l); err != nil {
			t.Fatalf("before the switch: %v", err)
		}
	}
	if err := take(st, links[2]); err == nil || !strings.Contains(err.Error(), "key in force") {
		t.Fatalf("the retired key at its switch: %v", err)
	}
}

// dos-2, A6, fuzz-3: a state changed on disk, carried in from another key, or out of shape is refused, never served.
func TestAChangedStateIsRefused(t *testing.T) {
	c := newCustodian(t)
	chain(t, c, 2, "2026-11-07T12:00:00Z")
	raw, _ := os.ReadFile(statePath(c.dir))
	lowered := strings.Replace(string(raw), `"size": 2`, `"size": 1`, 1)
	if _, err := openState([]byte(lowered), c.key); err == nil {
		t.Fatal("a lowered size loaded")
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := openState(raw, other); err == nil {
		t.Fatal("a state sealed under another key loaded")
	}
	bad := c.st.clone()
	bad.Key = ""
	if err := save(c.dir, bad, c.key); err == nil {
		t.Fatal("an inconsistent state was written")
	}
}

// A5, exposure-3: an exporter is retired; its directory takes no import and serves nothing.
func TestAnExporterIsRetired(t *testing.T) {
	c := newCustodian(t)
	chain(t, c, 1, "2026-11-07T12:00:00Z")
	out := c.dir + "-watermark.json"
	if err := export(c.dir, out, c.key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath(c.dir)); err == nil {
		t.Fatal("the live state is still there")
	}
	if _, err := load(c.dir, c.key); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("the exporter loads: %v", err)
	}
	if _, err := importState(c.dir, out, c.key); err == nil {
		t.Fatal("an import into the retired directory")
	}
	moved := t.TempDir()
	if st, err := importState(moved, out, c.key); err != nil || st.Size != 1 {
		t.Fatalf("an import elsewhere: %v", err)
	}
}
