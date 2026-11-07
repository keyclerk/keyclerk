// SPDX-License-Identifier: EUPL-1.2

package main

// The custodian's state: everything it decides by, written before every answer, and only ever moving forward. It is
// sealed with an HMAC keyed from the records key, so a state edited, bit-rotted or carried in from another key is
// refused, never served (decision 0033 point 4; review 2026-11-07 dos-2, A6, fuzz-3); and the state directory is held
// by one process at a time (A5).

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const stateFormat = "kc-custodian-state-v2"

// node is one perfect subtree of the frontier (merkle.py): its height and hash.
type node struct {
	H    int    `json:"h"`
	Hash string `json:"hash"`
}

// Retired is a key that signed this log until a position, destroyed here (#41 F7): links before Until may carry it,
// nothing after (review A13).
type Retired struct {
	Key   string `json:"key"`
	Until int64  `json:"until"`
}

// Witness is the floor: the largest checkpoint the witness countersigned that this custodian has seen. The custodian
// never goes below it and never signs at a position it passed (point 2's HA rule, point 5; review A2, A3, A10).
type Witness struct {
	Size int64  `json:"size"`
	Root string `json:"root"`
}

// Recovered is what the signer records in the log after a recovery (decision 0033 Q6): the statement the trustees
// signed (its sha256), the size it named, and who signed it.
type Recovered struct {
	Statement string   `json:"statement"`
	Size      int64    `json:"size"`
	Trustees  []string `json:"trustees"`
}

type State struct {
	Format     string     `json:"format"`
	Realm      string     `json:"realm"`
	Origin     string     `json:"origin"`  // the current key's log origin
	Origins    []string   `json:"origins"` // every origin of this log, oldest first (a new key is a new origin)
	Key        string     `json:"key"`     // the public key in use, hex
	Retired    []Retired  `json:"retired"`
	Size       int64      `json:"size"`
	Head       string     `json:"head"`
	Fence      int64      `json:"fence"`
	Frontier   []node     `json:"frontier"`
	LastBody   string     `json:"last_body"`  // sha256 of the message signed at position size-1
	LastSig    string     `json:"last_sig"`   // its signature: the same body again gets the same answer
	Checkpoint int64      `json:"checkpoint"` // the largest size a checkpoint, note or snapshot was signed for
	SnapSize   int64      `json:"snap_size"`  // one snapshot statement per size (review A8)
	SnapBody   string     `json:"snap_body"`
	Witness    Witness    `json:"witness"`
	Recovered  *Recovered `json:"recovered,omitempty"` // the last recovery, for the signer's marker in the log (Q6)
	// the TPM counter binding this state (point 5): absent without a TPM, so older states seal as before
	TPMCounter     uint32 `json:"tpm_counter,omitempty"`
	Counter        uint64 `json:"counter,omitempty"`
	CounterPending bool   `json:"counter_pending,omitempty"`
	CounterAt      int64  `json:"counter_at,omitempty"`
	MAC            string `json:"mac"`
}

func leaf(d []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, d...))
	return h[:]
}

func inner(l, r []byte) []byte {
	b := append([]byte{1}, l...)
	h := sha256.Sum256(append(b, r...))
	return h[:]
}

func unhex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func (s *State) push(h []byte) {
	f := append(s.Frontier, node{0, hex.EncodeToString(h)})
	for len(f) > 1 && f[len(f)-1].H == f[len(f)-2].H {
		l, r := f[len(f)-2], f[len(f)-1]
		f = append(f[:len(f)-2], node{l.H + 1, hex.EncodeToString(inner(unhex(l.Hash), unhex(r.Hash)))})
	}
	s.Frontier = f
}

func (s *State) root() []byte {
	if len(s.Frontier) == 0 {
		h := sha256.Sum256(nil)
		return h[:]
	}
	r := unhex(s.Frontier[len(s.Frontier)-1].Hash)
	for i := len(s.Frontier) - 2; i >= 0; i-- {
		r = inner(unhex(s.Frontier[i].Hash), r)
	}
	return r
}

func (s *State) clone() *State {
	c := *s
	c.Frontier = append([]node(nil), s.Frontier...)
	c.Retired = append([]Retired(nil), s.Retired...)
	c.Origins = append([]string(nil), s.Origins...)
	return &c
}

func (s *State) knowsOrigin(o string) bool {
	for _, x := range s.Origins {
		if x == o {
			return true
		}
	}
	return false
}

// consistent is the state's own shape: what a valid MAC still could not promise if the code that wrote it was wrong.
func (s *State) consistent() error {
	if s.Format != stateFormat || s.Realm == "" || !checkName(s.Origin) || !hex64.MatchString(s.Key) || !s.knowsOrigin(s.Origin) {
		return errors.New("the state's realm, origin or key is not in its shape")
	}
	if s.Size < 0 || s.Fence < 1 || s.Checkpoint < 0 || s.Checkpoint > s.Size || s.Witness.Size < 0 {
		return errors.New("the state's numbers are not in their range")
	}
	var total int64
	for i, n := range s.Frontier {
		if n.H < 0 || n.H > 62 || !hex64.MatchString(n.Hash) || (i > 0 && n.H >= s.Frontier[i-1].H) {
			return errors.New("the state's frontier is not a frontier")
		}
		total += 1 << n.H
	}
	if total != s.Size {
		return errors.New("the state's frontier does not add up to its size")
	}
	if s.Size == 0 {
		if s.Head != "" || s.LastBody != "" || s.LastSig != "" {
			return errors.New("an empty state names a head")
		}
	} else if !hex64.MatchString(s.Head) || !hex64.MatchString(s.LastBody) || !hex128.MatchString(s.LastSig) {
		return errors.New("the state's head or last link is not in its shape")
	}
	if s.Witness.Size > 0 && !hex64.MatchString(s.Witness.Root) {
		return errors.New("the state's witness floor is not in its shape")
	}
	for _, r := range s.Retired {
		if !hex64.MatchString(r.Key) || r.Until < 0 || r.Until > s.Size || r.Key == s.Key {
			return errors.New("the state's retired keys are not in their shape")
		}
	}
	return nil
}

func (s *State) seal(key crypto.Signer) ([]byte, error) {
	s.MAC = ""
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, macKey(key))
	m.Write(body)
	s.MAC = hex.EncodeToString(m.Sum(nil))
	return json.MarshalIndent(s, "", " ")
}

// open reads a sealed state: its MAC under this key, its own consistency; anything else is refused, never a first run.
func openState(raw []byte, key crypto.Signer) (*State, error) {
	var s State
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, errors.New("the state does not read: restore it through the recovery ceremony, never start empty")
	}
	got := s.MAC
	s.MAC = ""
	body, _ := json.Marshal(&s)
	m := hmac.New(sha256.New, macKey(key))
	m.Write(body)
	if !hmac.Equal(unhex(got), m.Sum(nil)) {
		return nil, errors.New("the state's seal does not hold under this key: it was changed, or is another key's; " +
			"recover it through the ceremony")
	}
	s.MAC = got
	if err := s.consistent(); err != nil {
		return nil, err
	}
	return &s, nil
}

func statePath(dir string) string { return filepath.Join(dir, "custodian-state.json") }
func tombPath(dir string) string  { return filepath.Join(dir, "custodian-retired") }
func lockPath(dir string) string  { return filepath.Join(dir, "custodian.lock") }

func load(dir string, key crypto.Signer) (*State, error) {
	if _, err := os.Stat(tombPath(dir)); err == nil {
		return nil, errors.New("this custodian exported its state and is retired: it never serves again")
	}
	raw, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no state: a missing state is never a first run; for a new log run init, for an existing " +
			"or lost one the recovery ceremony")
	}
	if err != nil {
		return nil, err
	}
	return openState(raw, key)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if runtime.GOOS != "windows" { // a directory cannot be synced there; the rename is durable on NTFS
		d, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}

func save(dir string, s *State, key crypto.Signer) error {
	if err := s.consistent(); err != nil {
		return fmt.Errorf("refusing to write an inconsistent state: %w", err)
	}
	raw, err := s.seal(key)
	if err != nil {
		return err
	}
	return writeAtomic(statePath(dir), append(raw, '\n'))
}

// lockDir holds the state directory for this process: another live custodian holding it is refused; a lock left by
// a process that is gone is taken over.
func lockDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := lockPath(dir)
	for i := 0; i < 2; i++ {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Sync()
			_ = f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		raw, rerr := os.ReadFile(p)
		pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
		if rerr == nil && perr == nil && pidAlive(pid) {
			return nil, fmt.Errorf("another custodian (process %d) holds %s: one process per state", pid, dir)
		}
		_ = os.Remove(p) // its holder is gone
	}
	return nil, errors.New("the state directory's lock could not be taken")
}
