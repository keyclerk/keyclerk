// SPDX-License-Identifier: EUPL-1.2

package main

// Decision 0033 points 5 and 6 against a TPM simulator: KC_TPM_SIM=tcp:HOST:PORT names one (swtpm socket --tpm2
// --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear); without it these skip.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func simTPM(t *testing.T) transport.TPMCloser {
	t.Helper()
	spec := os.Getenv("KC_TPM_SIM")
	if spec == "" {
		t.Skip("no TPM simulator (KC_TPM_SIM=tcp:HOST:PORT)")
	}
	tp, err := openTPM(spec)
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal with %q, got %v", want, err)
	}
}

func TestTheKeyIsSealedToTheBootState(t *testing.T) {
	tp := simTPM(t)
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	s, err := sealKey(tp, seed, []uint{16})
	if err != nil {
		t.Fatal(err)
	}
	k, err := unsealKey(tp, s)
	if err != nil || !bytes.Equal(k.Seed(), seed) {
		t.Fatalf("unseal: %v", err)
	}
	if _, err := (tpm2.PCRExtend{PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(16), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32)}}}}).Execute(tp); err != nil {
		t.Fatal(err)
	}
	_, err = unsealKey(tp, s) // another boot state: the file does not open
	wantErr(t, err, "boot state")
	again, err := sealKey(tp, seed, []uint{16})
	if err != nil {
		t.Fatal(err)
	}
	tp.Close() // the simulator serves one client: readKey opens its own
	path := filepath.Join(t.TempDir(), "records.sealed")
	if err := writeSealed(path, again); err != nil {
		t.Fatal(err)
	}
	got, err := readKey(path, os.Getenv("KC_TPM_SIM"))
	if err != nil || pubHex(got) != pubHex(ed25519.NewKeyFromSeed(seed)) {
		t.Fatalf("readKey of the sealed file: %v", err)
	}
	_, err = readKey(path, "")
	wantErr(t, err, "start with --tpm")
	wantErr(t, writeSealed(path, again), "never overwritten")
}

func TestTheStateIsBoundToTheTPMCounter(t *testing.T) {
	tp := simTPM(t)
	defer tp.Close()
	c := newCustodian(t)
	idx := uint32(0x01810C10)
	if err := defineCounter(tp, idx, c.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		pub, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(idx)}.Execute(tp)
		_, _ = tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner,
			NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(idx), Name: pub.NVName}}.Execute(tp)
	}()
	unbound, _ := os.ReadFile(statePath(c.dir))
	ctr := &tpmCounter{t: tp, index: idx, auth: counterAuth(c.key)}
	start := func(rebind bool) (*Custodian, error) {
		d, err := open(c.dir, "example", c.key)
		if err != nil {
			return nil, err
		}
		d.counter, d.epoch = ctr, time.Hour
		return d, d.checkCounter(rebind)
	}
	d, err := start(false) // a counter never raised: the state binds to it
	if err != nil || d.st.TPMCounter != idx || d.st.CounterPending {
		t.Fatalf("bind: %v %+v", err, d.st)
	}
	first := d.st.Counter

	// a crash after "pending" and before the TPM: the next start raises it
	p := d.st.clone()
	p.CounterPending = true
	if err := save(c.dir, p, c.key); err != nil {
		t.Fatal(err)
	}
	if d, err = start(false); err != nil || d.st.Counter != first+1 || d.st.CounterPending {
		t.Fatalf("finish before the TPM: %v %+v", err, d.st)
	}
	// a crash after the TPM and before the state: the next start settles it, never a rollback
	p = d.st.clone()
	p.CounterPending = true
	if err := save(c.dir, p, c.key); err != nil {
		t.Fatal(err)
	}
	if _, err := ctr.raise(); err != nil {
		t.Fatal(err)
	}
	if d, err = start(false); err != nil || d.st.Counter != first+2 || d.st.CounterPending {
		t.Fatalf("settle after the TPM: %v %+v", err, d.st)
	}

	// a checkpoint epoch raises it with the state, before the answer
	chain(t, d, 2, "2026-11-07T10:00:00Z")
	d.epoch = 0
	note := d.st.Origin + "\n2\n" + base64.StdEncoding.EncodeToString(d.st.root()) + "\n"
	if _, err := d.Sign([]byte(note)); err != nil {
		t.Fatal(err)
	}
	if d.st.Counter != first+3 {
		t.Fatalf("an epoch's checkpoint did not raise the counter: %d", d.st.Counter)
	}

	// the state copied back from before: refused, even without the witness
	backup, _ := os.ReadFile(statePath(c.dir))
	if err := d.raiseCounter(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath(c.dir), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = start(false)
	wantErr(t, err, "older than this custodian's last")
	_, err = start(true) // a recovery's rebind does not excuse a bound state
	wantErr(t, err, "older than this custodian's last")

	// a state from before the binding: refused at a start, bound again only by a recovery or an import
	if err := os.WriteFile(statePath(c.dir), unbound, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = start(false)
	wantErr(t, err, "raised before")
	if d, err = start(true); err != nil || d.st.Counter != first+5 {
		t.Fatalf("rebind at recovery: %v %+v", err, d.st)
	}

	// started without the counter, a bound state is refused
	plain, _ := open(c.dir, "example", c.key)
	wantErr(t, plain.checkCounter(false), "bound to the TPM counter at "+"0x"+strconv.FormatUint(uint64(idx), 16))
}
