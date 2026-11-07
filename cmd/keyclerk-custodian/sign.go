// SPDX-License-Identifier: EUPL-1.2

package main

// What the custodian signs, and nothing else (decision 0033 points 2 and 3). Each request is classified by a strict
// parse and checked against the state; the state it leads to is written; only then is it signed and answered, all in
// one critical section. Anything that is not a link, a checkpoint, a snapshot statement, a C2SP checkpoint note or a
// log line's hash is refused: nothing falls through to a signature unchecked (review 2026-11-07 A1, fuzz-1).

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const (
	linkLabel  = "kc-change-link-v1"
	cpLabel    = "kc-checkpoint-v1"
	snapLabel  = "kc-snapshot-v1"
	maxLink    = 1 << 20 // bytes of one link's body (link.MAX_LINK)
	maxPerKind = 500     // records of one kind one change may touch (decision 0022)
	zero       = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	utcTime   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	labelLine = regexp.MustCompile(`^kc-[a-z0-9-]+-v[0-9]+$`)
	lineHash  = regexp.MustCompile(`^[0-9a-f]{64}$`) // a log line's sha256, the signer's sign_line
)

type Custodian struct {
	mu          sync.Mutex
	dir         string
	key         crypto.Signer
	st          *State
	witnessVkey string        // the witness whose word lets this custodian follow (HA) and sets its floor
	token       string        // required on every request when set (always over TCP)
	counter     *tpmCounter   // the TPM counter binding the state, or nil
	epoch       time.Duration // how often the counter is raised (Q8)
	follow      *follow       // a follow under way: one at a time, owned by one connection
}

type refusal struct{ why string }

func (r refusal) Error() string { return r.why }

func refuse(format string, a ...any) error { return refusal{fmt.Sprintf(format, a...)} }

// Sign checks data against the state, persists the state it leads to, then signs.
func (c *Custodian) Sign(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.follow != nil {
		return nil, refuse("a follow is under way: nothing is signed until it ends")
	}
	if c.st.Size < c.st.Witness.Size {
		return nil, refuse("this custodian holds %d links and the witness countersigned %d: it follows the committed "+
			"log before it signs again", c.st.Size, c.st.Witness.Size)
	}
	if label, raw, ok := splitLabel(data); ok {
		switch label {
		case linkLabel:
			return c.signLink(data, raw)
		case cpLabel:
			return c.signCheckpoint(data, raw)
		case snapLabel:
			return c.signSnapshot(data, raw)
		}
		return nil, refuse("%s: not a statement this custodian signs", label)
	}
	if lineHash.Match(data) {
		return sign(c.key, data) // a log line's hash: no position, no tree
	}
	if bytes.Count(data, []byte("\n")) == 0 {
		return nil, refuse("not a link, checkpoint, snapshot statement, checkpoint note or log line hash: refused")
	}
	origin, size, root, err := checkpointText(data)
	if err != nil {
		return nil, refuse("not a link, checkpoint, snapshot statement or log line hash, and not a checkpoint note: %v", err)
	}
	return c.signNote(data, origin, size, root)
}

func splitLabel(data []byte) (string, []byte, bool) {
	i := bytes.IndexByte(data, '\n')
	if i < 0 || !labelLine.Match(data[:i]) {
		return "", nil, false
	}
	return string(data[:i]), data[i+1:], true
}

func (c *Custodian) signLink(data, raw []byte) ([]byte, error) {
	s := c.st
	if len(raw) > maxLink {
		return nil, refuse("a link body is at most %d bytes", maxLink)
	}
	seq, prev, fence, realm, err := linkBody(raw)
	if err != nil {
		return nil, err
	}
	if realm != s.Realm {
		return nil, refuse("a link for realm %s, and this custodian signs for %s only", realm, s.Realm)
	}
	body := sha256.Sum256(data)
	if s.Size > 0 && seq == s.Size-1 { // the same body again: the same signature; another one: never
		if hex.EncodeToString(body[:]) == s.LastBody {
			return unhex(s.LastSig), nil
		}
		return nil, refuse("position %d is signed already, with another body: one body per position", seq)
	}
	if seq != s.Size {
		return nil, refuse("link %d where link %d comes next", seq, s.Size)
	}
	head := zero
	if s.Size > 0 {
		head = s.Head
	}
	if prev != head {
		return nil, refuse("link %d does not name the last link's hash", seq)
	}
	if fence < s.Fence {
		return nil, refuse("fence %d is below %d: never lower than the last", fence, s.Fence)
	}
	sig, err := sign(c.key, data)
	if err != nil {
		return nil, fmt.Errorf("the key did not sign, nothing changed: %w", err)
	}
	next := s.clone()
	h := leaf(append(append([]byte(nil), data...), sig...)) // merkle.py: the signed message and its signature
	next.push(h)
	next.Size, next.Head, next.Fence = s.Size+1, hex.EncodeToString(h), fence
	next.LastBody, next.LastSig = hex.EncodeToString(body[:]), hex.EncodeToString(sig)
	if err := save(c.dir, next, c.key); err != nil {
		return nil, fmt.Errorf("the state was not written, nothing signed: %w", err)
	}
	c.st = next
	return sig, nil
}

func (c *Custodian) overOwn(size int64, root, head any) error {
	s := c.st
	if size < 1 || size != s.Size {
		return refuse("a statement over %d links, and this custodian signed %d", size, s.Size)
	}
	if root != hex.EncodeToString(s.root()) || head != s.Head {
		return refuse("a statement whose root or head is not the one this custodian computed")
	}
	return nil
}

func (c *Custodian) signCheckpoint(data, raw []byte) ([]byte, error) {
	b, size, err := checkpointBody(raw)
	if err != nil {
		return nil, err
	}
	if b["realm"] != c.st.Realm {
		return nil, refuse("a checkpoint for another realm")
	}
	if err := c.overOwn(size, b["root"], b["head"]); err != nil {
		return nil, err
	}
	return c.signAt(data, size, nil)
}

func (c *Custodian) signSnapshot(data, raw []byte) ([]byte, error) {
	b, size, err := snapshotBody(raw)
	if err != nil {
		return nil, err
	}
	if b["realm"] != c.st.Realm {
		return nil, refuse("a snapshot for another realm")
	}
	if err := c.overOwn(size, b["root"], b["head"]); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	body := hex.EncodeToString(sum[:])
	if size < c.st.SnapSize || (size == c.st.SnapSize && body != c.st.SnapBody) {
		return nil, refuse("a snapshot statement over %d links after another one over %d: one per size, never lower",
			size, c.st.SnapSize)
	}
	return c.signAt(data, size, func(n *State) { n.SnapSize, n.SnapBody = size, body })
}

func (c *Custodian) signNote(data []byte, origin string, size int64, root []byte) ([]byte, error) {
	if origin != c.st.Origin {
		return nil, refuse("a checkpoint note under origin %s, and this key signs under %s", origin, c.st.Origin)
	}
	if size < 1 || size != c.st.Size || !bytes.Equal(root, c.st.root()) {
		return nil, refuse("a checkpoint note whose size or root is not the one this custodian computed")
	}
	return c.signAt(data, size, nil)
}

func (c *Custodian) signAt(data []byte, size int64, also func(*State)) ([]byte, error) {
	if size < c.st.Checkpoint {
		return nil, refuse("a statement over %d links after one over %d: never lower", size, c.st.Checkpoint)
	}
	if size > c.st.Checkpoint || also != nil {
		next := c.st.clone()
		next.Checkpoint = size
		if also != nil {
			also(next)
		}
		if err := save(c.dir, next, c.key); err != nil {
			return nil, fmt.Errorf("the state was not written, nothing signed: %w", err)
		}
		c.st = next
		if c.epochDue() { // a checkpoint epoch: the counter moves with the state before the answer
			if err := c.raiseCounter(); err != nil {
				return nil, fmt.Errorf("nothing signed: %w", err)
			}
		}
	}
	return sign(c.key, data)
}
