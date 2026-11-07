// SPDX-License-Identifier: EUPL-1.2

package main

// Two signer nodes, one custodian each with the same key (decision 0033 Q4): a standby's custodian follows the links
// the active node committed, on the commit witness's countersigned note. A follow is one staged operation, owned by one
// connection (follow_begin, follow_links, follow_end), accepted only when it lands exactly on the witness's size and
// root; while it is under way nothing is signed. It never goes below the witness floor and never below the custodian's
// own size: a custodian never re-signs a position it signed (review 2026-11-07 A2, A3, A4, dos-1). Extend continues
// its own state; rebuild starts from link 0, for a deposed node whose own tail the committed log replaced, once the
// witness has passed that tail.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type sealedLink struct {
	Bytes     string `json:"bytes"`
	Signature string `json:"signature"`
}

type follow struct {
	owner    uint64
	st       *State
	size     int64
	root     []byte
	baseSize int64
	baseHead string
}

// keyFor is the key that may have signed a link at seq: the current key from its switch on, a retired key before
// the position it stopped at (A13).
func keyFor(st *State, seq int64, verify func(pub []byte) bool) bool {
	var from int64
	for _, r := range st.Retired {
		if r.Until > from {
			from = r.Until
		}
		if seq < r.Until && verify(unhex(r.Key)) {
			return true
		}
	}
	return seq >= from && verify(unhex(st.Key))
}

// take checks one sealed link as the next of st, as the stores check it, and moves st past it.
func take(st *State, l sealedLink) error {
	raw, err1 := base64.StdEncoding.Strict().DecodeString(l.Bytes)
	sig, err2 := hex.DecodeString(l.Signature)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize || !hex128.MatchString(l.Signature) {
		return refuse("link %d is not a sealed link", st.Size)
	}
	if len(raw) > maxLink {
		return refuse("link %d is over %d bytes", st.Size, maxLink)
	}
	seq, prev, fence, realm, err := linkBody(raw) // diff-9: the full shape, as signLink checks it
	if err != nil {
		return refuse("link %d: %v", st.Size, err)
	}
	msg := append([]byte(linkLabel+"\n"), raw...)
	if !keyFor(st, seq, func(pub []byte) bool { return ed25519.Verify(ed25519.PublicKey(pub), msg, sig) }) {
		return refuse("link %d is not signed by the key in force at that position", seq)
	}
	head := zero
	if st.Size > 0 {
		head = st.Head
	}
	if seq != st.Size || prev != head || realm != st.Realm || fence < st.Fence {
		return refuse("link %d does not follow the state at %d", seq, st.Size)
	}
	h := leaf(append(append([]byte(nil), msg...), sig...))
	st.push(h)
	body := sha256.Sum256(msg)
	st.Size, st.Head, st.Fence = st.Size+1, hex.EncodeToString(h), fence
	st.LastBody, st.LastSig = hex.EncodeToString(body[:]), hex.EncodeToString(sig)
	return nil
}

type followReq struct {
	Op    string       `json:"op"`
	Mode  string       `json:"mode"`
	Note  string       `json:"note"`
	Links []sealedLink `json:"links"`
}

func (c *Custodian) followOp(line []byte, owner uint64) map[string]any {
	var req followReq
	if err := json.Unmarshal(line, &req); err != nil {
		return map[string]any{"refused": "a follow request is {op, mode, note, links}"}
	}
	if c.witnessVkey == "" {
		return map[string]any{"refused": "this custodian follows another node only on the witness's word: serve it " +
			"with --witness-vkey"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.follow != nil && c.follow.owner != owner {
		return map[string]any{"refused": "another connection's follow is under way"}
	}
	switch req.Op {
	case "follow_begin":
		origin, size, root, err := cosigned(req.Note, c.witnessVkey)
		if err != nil {
			return map[string]any{"refused": err.Error()}
		}
		if !c.st.knowsOrigin(origin) {
			return map[string]any{"refused": fmt.Sprintf("a note under origin %s, not one of this log's", origin)}
		}
		if size < c.st.Witness.Size || (size == c.st.Witness.Size && size > 0 &&
			hex.EncodeToString(root) != c.st.Witness.Root) {
			return map[string]any{"refused": fmt.Sprintf("a note over %d links, and the witness countersigned %d "+
				"already: never below the floor", size, c.st.Witness.Size)}
		}
		if size < c.st.Size {
			return map[string]any{"refused": fmt.Sprintf("the witness countersigned %d links and this custodian signed "+
				"%d: it waits until the committed log passes its own, and never signs a position twice", size, c.st.Size)}
		}
		var cand *State
		switch req.Mode {
		case "extend":
			cand = c.st.clone()
		case "rebuild":
			cand = c.st.clone()
			cand.Size, cand.Head, cand.Fence, cand.Frontier = 0, "", 1, []node{}
			cand.LastBody, cand.LastSig = "", ""
		default:
			return map[string]any{"refused": "mode is extend or rebuild"}
		}
		c.follow = &follow{owner: owner, st: cand, size: size, root: root, baseSize: c.st.Size, baseHead: c.st.Head}
		return map[string]any{"size": cand.Size}
	case "follow_links":
		f := c.follow
		if f == nil {
			return map[string]any{"refused": "no follow begun"}
		}
		for _, l := range req.Links {
			if err := take(f.st, l); err != nil {
				c.follow = nil
				return map[string]any{"refused": err.Error()}
			}
			if f.st.Size > f.size {
				c.follow = nil
				return map[string]any{"refused": "more links than the witness countersigned"}
			}
		}
		return map[string]any{"size": f.st.Size}
	case "follow_end":
		f := c.follow
		c.follow = nil
		if f == nil {
			return map[string]any{"refused": "no follow begun"}
		}
		if c.st.Size != f.baseSize || c.st.Head != f.baseHead {
			return map[string]any{"refused": "the state moved while the follow was under way: nothing changed"}
		}
		if f.st.Size != f.size || !bytes.Equal(f.st.root(), f.root) || f.st.Size < c.st.Size {
			return map[string]any{"refused": "these links are not the tree the witness countersigned: nothing changed"}
		}
		f.st.Witness = Witness{Size: f.size, Root: hex.EncodeToString(f.root)}
		if err := save(c.dir, f.st, c.key); err != nil {
			return map[string]any{"refused": "the state was not written: " + err.Error()}
		}
		c.st = f.st
		return map[string]any{"size": c.st.Size}
	}
	return map[string]any{"refused": "unknown op"}
}

// dropFollow ends a follow whose connection went away.
func (c *Custodian) dropFollow(owner uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.follow != nil && c.follow.owner == owner {
		c.follow = nil
	}
}
