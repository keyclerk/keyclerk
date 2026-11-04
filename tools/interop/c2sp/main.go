// SPDX-License-Identifier: EUPL-1.2

// Command c2sp writes tests/conformance/c2sp-go.json: checkpoints, cosignatures and consistency proofs made by
// independent Go implementations of C2SP (golang.org/x/mod/sumdb/note and tlog, filippo.io/torchwood), which
// keyclerk/store/note.py and merkle.py must reproduce byte for byte (tests/test_c2sp.py). The keys come from fixed
// seeds and Ed25519 is deterministic; only the cosignature times change from run to run.
//
//	cd tools/interop/c2sp && go run . > ../../../tests/conformance/c2sp-go.json
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	origin  = "keyclerk.example/c2sp-vector"
	witness = "witness.example/c2sp-vector"
	leaves  = 21
)

func keyID(name string, alg byte, pub []byte) uint32 {
	h := sha256.Sum256(append(append([]byte(name+"\n"), alg), pub...))
	return binary.BigEndian.Uint32(h[:4])
}

func vkey(name string, alg byte, pub []byte) string {
	return fmt.Sprintf("%s+%08x+%s", name, keyID(name, alg, pub), base64.StdEncoding.EncodeToString(append([]byte{alg}, pub...)))
}

type checkpoint struct {
	Size  int64  `json:"size"`
	Root  string `json:"root"`
	Note  string `json:"note"`
	Time  int64  `json:"cosignature_time"`
	Proof []struct {
		From  int64    `json:"from"`
		Proof []string `json:"proof"`
	} `json:"proofs"`
}

func main() {
	logSeed := sha256.Sum256([]byte("kc-c2sp-vector log key"))
	witSeed := sha256.Sum256([]byte("kc-c2sp-vector witness key"))
	logKey, witKey := ed25519.NewKeyFromSeed(logSeed[:]), ed25519.NewKeyFromSeed(witSeed[:])
	logPub, witPub := logKey.Public().(ed25519.PublicKey), witKey.Public().(ed25519.PublicKey)

	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", origin, keyID(origin, 1, logPub),
		base64.StdEncoding.EncodeToString(append([]byte{1}, logSeed[:]...)))
	logSigner, err := note.NewSigner(skey)
	check(err)
	cosigner, err := torchwood.NewCosignatureSigner(witness, witKey)
	check(err)
	if cosigner.KeyHash() != keyID(witness, 4, witPub) {
		panic("torchwood's cosigner key id is not SHA-256(name, 0x0A, 0x04, key)[:4]")
	}
	logVerifier, err := note.NewVerifier(vkey(origin, 1, logPub))
	check(err)
	cosigVerifier, err := torchwood.NewCosignatureVerifier(vkey(witness, 4, witPub))
	check(err)

	var data [][]byte
	var hashes []tlog.Hash
	reader := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = hashes[x]
		}
		return out, nil
	})
	for i := 0; i < leaves; i++ {
		d := []byte(fmt.Sprintf("kc-c2sp-vector link %d", i))
		data = append(data, d)
		hs, err := tlog.StoredHashes(int64(i), d, reader)
		check(err)
		hashes = append(hashes, hs...)
	}

	var cps []checkpoint
	sizes := []int64{1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 21}
	for _, n := range sizes {
		root, err := tlog.TreeHash(n, reader)
		check(err)
		text := fmt.Sprintf("%s\n%d\n%s\n", origin, n, base64.StdEncoding.EncodeToString(root[:]))
		if _, err := torchwood.ParseCheckpoint(text); err != nil {
			panic(err)
		}
		signed, err := note.Sign(&note.Note{Text: text}, logSigner, cosigner)
		check(err)
		parsed, err := note.Open(signed, note.VerifierList(logVerifier, cosigVerifier))
		check(err)
		var t int64 = -1
		for _, s := range parsed.Sigs {
			if s.Name == witness {
				t, err = torchwood.CosignatureTimestamp(s)
				check(err)
			}
		}
		cp := checkpoint{Size: n, Root: base64.StdEncoding.EncodeToString(root[:]), Note: string(signed), Time: t}
		for _, m := range sizes {
			if m >= n {
				break
			}
			p, err := tlog.ProveTree(n, m, reader)
			check(err)
			old, err := tlog.TreeHash(m, reader)
			check(err)
			check(tlog.CheckTree(p, n, root, m, old))
			var lines []string
			for _, h := range p {
				lines = append(lines, base64.StdEncoding.EncodeToString(h[:]))
			}
			cp.Proof = append(cp.Proof, struct {
				From  int64    `json:"from"`
				Proof []string `json:"proof"`
			}{m, lines})
		}
		cps = append(cps, cp)
	}

	var leafData []string
	for _, d := range data {
		leafData = append(leafData, string(d))
	}
	out := map[string]any{
		"about": "made by tools/interop/c2sp (golang.org/x/mod/sumdb/note and tlog, filippo.io/torchwood); " +
			"keyclerk must reproduce every note and proof byte for byte",
		"origin":       origin,
		"log_vkey":     vkey(origin, 1, logPub),
		"log_seed":     base64.StdEncoding.EncodeToString(logSeed[:]),
		"witness_vkey": vkey(witness, 4, witPub),
		"witness_seed": base64.StdEncoding.EncodeToString(witSeed[:]),
		"leaves":       leafData,
		"checkpoints":  cps,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	check(enc.Encode(out))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
