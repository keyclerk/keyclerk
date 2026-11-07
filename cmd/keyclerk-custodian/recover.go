// SPDX-License-Identifier: EUPL-1.2

package main

// The lost-state ceremony (decision 0033 point 4, Q6): a custodian whose state is lost, broken or behind the witness
// takes the log's links again, checked as adopt checks them, on a recovery statement the security officer and a root
// trust owner signed (the pinned trustee set's threshold, as keyclerk.trustees verifies it), never lower than the
// witness's countersigned checkpoint. The old state is kept beside the new one, as evidence.

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	recoveryLabel = "kc-custodian-recovery-v1"
	trusteesFmt   = "kc-trustees-v1"
	skPrefix      = "sk-ssh-ed25519" + "@" + "openssh.com"
	maxSig        = 16 * 1024
)

type trustee struct {
	ID     string `json:"trustee_id"`
	Anchor string `json:"anchor"`
	Role   string `json:"role"`
	Key    struct {
		Type      string `json:"type"`
		PublicKey string `json:"public_key"`
	} `json:"key"`
}

type trusteeSet struct {
	Format   string    `json:"format"`
	Realm    string    `json:"realm"`
	Version  int64     `json:"version"`
	Trustees []trustee `json:"trustees"`
	At       string    `json:"at"`
}

func sshString(b []byte, i int) ([]byte, int, error) {
	if i+4 > len(b) {
		return nil, 0, errors.New("an SSH string runs past the end")
	}
	n := int(binary.BigEndian.Uint32(b[i : i+4]))
	if n < 0 || i+4+n > len(b) {
		return nil, 0, errors.New("an SSH string runs past the end")
	}
	return b[i+4 : i+4+n], i + 4 + n, nil
}

func wire(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// verifySSHSIG follows OpenSSH's PROTOCOL.sshsig for ssh-ed25519 and sk-ssh-ed25519 (user presence required).
func verifySSHSIG(pubBlob []byte, sig, namespace string, message []byte) error {
	s := strings.TrimSpace(sig)
	if strings.HasPrefix(s, "-----BEGIN SSH SIGNATURE-----") {
		s = strings.TrimPrefix(s, "-----BEGIN SSH SIGNATURE-----")
		s = strings.Join(strings.Fields(strings.Split(s, "-----END SSH SIGNATURE-----")[0]), "")
	}
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(blob) < 10 || !bytes.HasPrefix(blob, []byte("SSHSIG")) || binary.BigEndian.Uint32(blob[6:10]) != 1 {
		return errors.New("not an SSHSIG version 1 signature")
	}
	i := 10
	var pub, ns, reserved, alg, sigblob []byte
	for _, p := range []*[]byte{&pub, &ns, &reserved, &alg, &sigblob} {
		if *p, i, err = sshString(blob, i); err != nil {
			return err
		}
	}
	if i != len(blob) || len(reserved) != 0 {
		return errors.New("trailing bytes, or a reserved field that is not empty")
	}
	if !bytes.Equal(pub, pubBlob) || string(ns) != namespace {
		return errors.New("signed by another key or in another namespace")
	}
	var h []byte
	switch string(alg) {
	case "sha256":
		x := sha256.Sum256(message)
		h = x[:]
	case "sha512":
		x := sha512.Sum512(message)
		h = x[:]
	default:
		return errors.New("SSHSIG hash sha256 or sha512 only")
	}
	signed := append(append(append(append([]byte("SSHSIG"), wire(ns)...), wire(reserved)...), wire(alg)...), wire(h)...)
	kt, j, err := sshString(pub, 0)
	if err != nil {
		return err
	}
	raw, j, err := sshString(pub, j)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("a malformed SSH Ed25519 key")
	}
	var app []byte
	if string(kt) == skPrefix {
		if app, _, err = sshString(pub, j); err != nil {
			return err
		}
	} else if string(kt) != "ssh-ed25519" {
		return errors.New("key type is not ssh-ed25519 or " + skPrefix)
	}
	st, k, err := sshString(sigblob, 0)
	if err != nil {
		return err
	}
	sig64, k, err := sshString(sigblob, k)
	if err != nil || string(st) != string(kt) || len(sig64) != ed25519.SignatureSize {
		return errors.New("the signature's type is not the key's")
	}
	if app != nil { // FIDO2: the authenticator signs its own envelope
		if k+5 != len(sigblob) || sigblob[k]&0x01 == 0 {
			return errors.New("a FIDO2 signature without user presence")
		}
		ah, sh := sha256.Sum256(app), sha256.Sum256(signed)
		signed = append(append(append(ah[:], sigblob[k]), sigblob[k+1:k+5]...), sh[:]...)
	} else if k != len(sigblob) {
		return errors.New("trailing bytes in the signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), signed, sig64) {
		return errors.New("the signature does not verify")
	}
	return nil
}

func (t trustee) verify(realm, label string, statement []byte, sig string) error {
	if len(sig) > maxSig {
		return errors.New("a signature of an insane size")
	}
	message := append([]byte(label+"\n"), statement...)
	switch t.Key.Type {
	case "ed25519":
		pub, err1 := hex.DecodeString(t.Key.PublicKey)
		s, err2 := hex.DecodeString(sig)
		if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, message, s) {
			return errors.New("the signature does not verify")
		}
		return nil
	case "ssh-ed25519", "sk-ssh-ed25519":
		blob, err := base64.StdEncoding.DecodeString(t.Key.PublicKey)
		if err != nil {
			return errors.New("the trustee's key does not decode")
		}
		return verifySSHSIG(blob, sig, "keyclerk-trustee@"+realm, message)
	}
	return errors.New("an unknown key type")
}

// threshold holds when the signatures make one officer and one root trust owner, two different people.
func threshold(ts *trusteeSet, label string, statement []byte, sigs map[string]string) ([]string, error) {
	var good []trustee
	var why []string
	for _, t := range ts.Trustees {
		sig, ok := sigs[t.ID]
		if !ok {
			continue
		}
		if err := t.verify(ts.Realm, label, statement, sig); err != nil {
			why = append(why, t.ID+": "+err.Error())
			continue
		}
		good = append(good, t)
	}
	for _, o := range good {
		for _, r := range good {
			if o.Role == "officer" && r.Role == "root" && o.Anchor != r.Anchor {
				return []string{o.ID, r.ID}, nil
			}
		}
	}
	return nil, fmt.Errorf("needs one officer and one root trust owner of the pinned set, two people (%s)",
		strings.Join(why, "; "))
}

// recovered is the ceremony (point 4, Q6), and the one way a log reaches a custodian (review 2026-11-07 A7: there is
// no other adopt): the log's links checked into a state equal to a kc-custodian-recovery-v1 statement that an officer
// and a root trust owner of the pinned set signed; never below a state this key can still read, never below the
// witness's countersigned checkpoint (unless the operator waives the witness, outside production).
type recovery struct {
	dir, realm, origin string
	origins            []string
	retired            []Retired
	key                crypto.Signer
	links, set, stmt   string
	sigs               map[string]string
	witnessURL, wVkey  string
	witnessLog         string
	unwitnessed        bool
}

func (r recovery) run() (*State, []string, error) {
	rawSet, err := os.ReadFile(r.set)
	if err != nil {
		return nil, nil, err
	}
	var ts trusteeSet
	dec := json.NewDecoder(bytes.NewReader(rawSet))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ts); err != nil || ts.Format != trusteesFmt || ts.Realm != r.realm {
		return nil, nil, errors.New("not a kc-trustees-v1 set for this realm (read strictly)")
	}
	stmt, err := os.ReadFile(r.stmt)
	if err != nil {
		return nil, nil, err
	}
	stmt = bytes.TrimSuffix(stmt, []byte("\n"))
	b, err := canonicalObject(stmt) // A9: the bytes the trustees signed say one thing, in every language
	if err != nil {
		return nil, nil, fmt.Errorf("the recovery statement: %v", err)
	}
	if !keysAre(b, "format", "realm", "origin", "size", "root", "head", "at") || b["format"] != recoveryLabel ||
		b["realm"] != r.realm || b["origin"] != r.origin {
		return nil, nil, errors.New("not a kc-custodian-recovery-v1 statement for this realm and origin")
	}
	size, ok := count(b["size"], 1)
	if !ok || hexAndTime(b, "root", "head") != nil {
		return nil, nil, errors.New("the statement's size, root, head or time is not in its shape")
	}
	who, err := threshold(&ts, recoveryLabel, stmt, r.sigs)
	if err != nil {
		return nil, nil, err
	}
	origins := r.origins
	if len(origins) == 0 || origins[len(origins)-1] != r.origin {
		origins = append(append([]string(nil), origins...), r.origin)
	}
	st := &State{Format: stateFormat, Realm: r.realm, Origin: r.origin, Origins: origins,
		Key: pubHex(r.key), Retired: append([]Retired(nil), r.retired...),
		Fence: 1, Frontier: []node{}}
	f, err := os.Open(r.links)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	rd := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := readLine(rd, maxRequest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var l sealedLink
		if err := json.Unmarshal(line, &l); err != nil {
			return nil, nil, fmt.Errorf("link %d does not read", st.Size)
		}
		if err := take(st, l); err != nil {
			return nil, nil, err
		}
	}
	if st.Size != size || hex.EncodeToString(st.root()) != b["root"] || st.Head != b["head"] {
		return nil, nil, errors.New("the links are not the log the statement names (size, root, head)")
	}
	if old, err := load(r.dir, r.key); err == nil { // a state this key still reads: only raised
		if st.Size < old.Size {
			return nil, nil, fmt.Errorf("the recovery names %d links and this custodian's state %d: a recovery only raises",
				st.Size, old.Size)
		}
		st.Checkpoint, st.SnapSize, st.SnapBody, st.Witness = old.Checkpoint, old.SnapSize, old.SnapBody, old.Witness
		if st.Size == old.Size && st.Head != old.Head {
			return nil, nil, errors.New("the recovery names another log at this custodian's size")
		}
	}
	switch {
	case r.witnessURL != "":
		log := r.witnessLog
		if log == "" {
			log = origins[0]
		}
		w, err := floor(st, r.witnessURL, log, r.wVkey)
		if err != nil {
			return nil, nil, err
		}
		st.Witness = w
	case !r.unwitnessed:
		return nil, nil, errors.New("a recovery reads the witness (--witness URL --witness-vkey VKEY): outside production " +
			"only, --unwitnessed")
	}
	if _, err := os.Stat(statePath(r.dir)); err == nil {
		evidence := statePath(r.dir) + ".lost-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(statePath(r.dir), evidence); err != nil {
			return nil, nil, err
		}
	}
	digest := sha256.Sum256(stmt)
	st.Recovered = &Recovered{Statement: hex.EncodeToString(digest[:]), Size: size, Trustees: who}
	return st, who, save(r.dir, st, r.key)
}
