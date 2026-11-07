// SPDX-License-Identifier: EUPL-1.2

package main

// The witness (decision 0033 point 5): its countersigned checkpoint is the custodian's floor. The cosignature is
// checked byte for byte as keyclerk/store/note.py checks it, and the check fails closed (review 2026-11-07 A10).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// parseVkey is note.parse_vkey for a cosigner key: name+keyid+base64(0x04 || key), the key id the name and key give.
func parseVkey(vkey string) (string, []byte, ed25519.PublicKey, error) {
	parts := strings.SplitN(vkey, "+", 3) // the name holds no plus; base64 may
	if len(parts) != 3 || len(parts[1]) != 8 || !checkName(parts[0]) {
		return "", nil, nil, errors.New("a verifier key is name+keyid+base64(type || key)")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(raw) != 33 || raw[0] != 0x04 || base64.StdEncoding.EncodeToString(raw) != parts[2] {
		return "", nil, nil, errors.New("not a cosignature (type 0x04) Ed25519 verifier key in canonical base64")
	}
	h := sha256.Sum256(append([]byte(parts[0]+"\n"), raw...))
	if hex.EncodeToString(h[:4]) != parts[1] {
		return "", nil, nil, errors.New("the verifier key's id does not match its name and key")
	}
	return parts[0], h[:4], ed25519.PublicKey(raw[1:]), nil
}

// cosigned reads a note (a checkpoint text, an empty line, signature lines) and returns its origin, size and root once
// the pinned witness's cosignature over the text verifies.
func cosigned(note, vkey string) (string, int64, []byte, error) {
	name, id, pub, err := parseVkey(vkey)
	if err != nil {
		return "", 0, nil, err
	}
	i := strings.Index(note, "\n\n")
	if i < 0 {
		return "", 0, nil, errors.New("not a note")
	}
	text := note[:i+1]
	origin, size, root, err := checkpointText([]byte(text))
	if err != nil {
		return "", 0, nil, fmt.Errorf("the note's checkpoint: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(note[i+2:], "\n"), "\n") {
		f := strings.Split(line, " ")
		if len(f) != 3 || f[0] != "—" || f[1] != name {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(f[2])
		if err != nil || len(raw) != 4+8+ed25519.SignatureSize || !bytes.Equal(raw[:4], id) {
			continue
		}
		t := binary.BigEndian.Uint64(raw[4:12])
		if ed25519.Verify(pub, []byte("cosignature/v1\ntime "+strconv.FormatUint(t, 10)+"\n"+text), raw[12:]) {
			return origin, size, root, nil
		}
	}
	return "", 0, nil, errors.New("the note carries no cosignature by the pinned witness key")
}

// witnessed fetches the witness's newest countersigned checkpoint of the log kept under logOrigin.
func witnessed(url, logOrigin, vkey string) (string, int64, []byte, bool, error) {
	if _, _, _, err := parseVkey(vkey); err != nil {
		return "", 0, nil, false, err
	}
	sum := sha256.Sum256([]byte(logOrigin))
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/" + hex.EncodeToString(sum[:]) + "/checkpoint")
	if err != nil {
		return "", 0, nil, false, err
	}
	defer resp.Body.Close()
	note, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", 0, nil, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, nil, false, fmt.Errorf("the witness answers %d", resp.StatusCode)
	}
	origin, size, root, err := cosigned(string(note), vkey)
	return origin, size, root, false, err
}

// floor reads the witness and returns the floor to keep: refused while the state is behind it, holds another tree at
// its size, or the witness keeps nothing of a log that has links.
func floor(st *State, url, logOrigin, vkey string) (Witness, error) {
	origin, size, root, none, err := witnessed(url, logOrigin, vkey)
	if err != nil {
		return Witness{}, fmt.Errorf("the witness cannot be checked (%v): this custodian does not serve until it can", err)
	}
	if none {
		if st.Size > 0 {
			return Witness{}, errors.New("the witness keeps no checkpoint of a log that has links: a wrong address or " +
				"--witness-log, or a witness seeded empty; this custodian does not serve")
		}
		return st.Witness, nil
	}
	if !st.knowsOrigin(origin) {
		return Witness{}, fmt.Errorf("the witness's checkpoint is under origin %s, not one of this log's", origin)
	}
	if size < st.Witness.Size {
		return Witness{}, fmt.Errorf("the witness shows %d links and countersigned %d before: a witness rolled back",
			size, st.Witness.Size)
	}
	if size == st.Witness.Size && size > 0 && hex.EncodeToString(root) != st.Witness.Root {
		return Witness{}, errors.New("the witness countersigned another tree at the floor's size")
	}
	if size == st.Size && size > 0 && !bytes.Equal(root, st.root()) {
		return Witness{}, errors.New("the witness countersigned another tree at this size: this state is not the log's")
	}
	// Behind the witness (a standby restarted, or a state restored from an older copy): it serves with the floor
	// raised and signs nothing until it has followed the committed log onto the witness's tree.
	return Witness{Size: size, Root: hex.EncodeToString(root)}, nil
}
