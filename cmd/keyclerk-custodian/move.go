// SPDX-License-Identifier: EUPL-1.2

package main

// Moving a custodian's state between machines (decision 0033 point 4: an exported watermark, both ends stopped, an
// import that only raises, the exporter retiring itself) and rotating its key (a planned rotation, #41 F7).

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"
)

// export writes the sealed state for another machine and retires this one: a tombstone it never serves past, and
// the live state overwritten and removed, so no copy of it here can be brought back (review 2026-11-07 A5,
// exposure-3).
func export(dir, out string, key crypto.Signer) error {
	st, err := load(dir, key)
	if err != nil {
		return err
	}
	raw, err := st.seal(key)
	if err != nil {
		return err
	}
	if err := writeAtomic(out, append(raw, '\n')); err != nil {
		return err
	}
	tomb := fmt.Sprintf("exported at %s: realm %s, %d links, head %s\n", time.Now().UTC().Format(time.RFC3339),
		st.Realm, st.Size, st.Head)
	if err := writeAtomic(tombPath(dir), []byte(tomb)); err != nil {
		return err
	}
	return destroy(statePath(dir))
}

// importState takes an exported state: sealed under this key and consistent (A6), into a directory with no tombstone,
// and over a state of the same realm and key only when it raises.
func importState(dir, from string, key crypto.Signer) (*State, error) {
	if _, err := os.Stat(tombPath(dir)); err == nil {
		return nil, errors.New("this directory's custodian exported its state and is retired: import on another machine")
	}
	raw, err := os.ReadFile(from)
	if err != nil {
		return nil, err
	}
	in, err := openState(raw, key)
	if err != nil {
		return nil, fmt.Errorf("the export: %w", err)
	}
	if cur, err := load(dir, key); err == nil {
		if cur.Realm != in.Realm || cur.Key != in.Key {
			return nil, errors.New("the import is for another realm or key")
		}
		same := in.Size == cur.Size && in.Head == cur.Head && in.LastSig == cur.LastSig
		if in.Size < cur.Size || (in.Size == cur.Size && !same) || in.Fence < cur.Fence ||
			in.Witness.Size < cur.Witness.Size || in.Checkpoint < cur.Checkpoint {
			return nil, errors.New("the import is not ahead of this state: an import only raises")
		}
	}
	in.TPMCounter, in.Counter, in.CounterPending, in.CounterAt = 0, 0, false, 0 // another machine's: this one binds its own
	return in, save(dir, in, key)
}

// rotate moves the custodian to the next key at the next link (a planned rotation; a recovery is the ceremony): the
// old key is recorded as retired until this position, the state sealed under the new key, the old key file destroyed.
func rotate(dir string, c *Custodian, next crypto.Signer, origin string, fromSeq int64, oldFile string) error {
	st := c.st
	if fromSeq != st.Size {
		return fmt.Errorf("the history switches at link %d, and this custodian signed %d: a planned rotation switches "+
			"at the next link; a recovery resets the custodian through the recovery ceremony", fromSeq, st.Size)
	}
	if !checkName(origin) || st.knowsOrigin(origin) {
		return errors.New("a new key is a new log origin: give --origin, one this log never had")
	}
	pub := pubHex(next)
	if pub == st.Key {
		return errors.New("the next key is the current one")
	}
	for _, r := range st.Retired {
		if r.Key == pub {
			return errors.New("the next key was used before: a key is used once")
		}
	}
	n := st.clone()
	n.TPMCounter, n.Counter, n.CounterPending, n.CounterAt = 0, 0, false, 0 // the new key binds a new counter (tpm-init)
	n.Retired = append(n.Retired, Retired{Key: st.Key, Until: st.Size})
	n.Key, n.Origin = pub, origin
	n.Origins = append(n.Origins, origin)
	if err := save(dir, n, next); err != nil {
		return err
	}
	return destroy(oldFile)
}

// destroy overwrites a file with random bytes, syncs it and removes it, reporting every failure. On journalled,
// copy-on-write or flash storage an overwrite is no erasure: copies (backups, snapshots, shadow copies) must be
// destroyed where they are (review 2026-11-07 exposure-4; a TPM or HSM key is the real answer, point 6).
func destroy(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		junk := make([]byte, info.Size())
		if _, err = rand.Read(junk); err == nil {
			if _, err = f.WriteAt(junk, 0); err == nil {
				err = f.Sync()
			}
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s was not overwritten: %w", path, err)
	}
	return os.Remove(path)
}
