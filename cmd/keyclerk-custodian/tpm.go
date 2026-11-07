// SPDX-License-Identifier: EUPL-1.2

// The TPM (decision 0033 points 5 and 6): it holds the counter that binds the state, and seals the key file to the
// machine's boot state; it never holds the key (no TPM on sale implements Ed25519). The counter is raised per
// checkpoint epoch and at recovery, not per link, because NV counters wear (Q8).
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

const sealedFormat = "kc-custodian-tpm-key-v1"

// openTPM: "device" is the operating system's TPM; "tcp:HOST:PORT" a TPM simulator (swtpm, mssim) for tests only.
func openTPM(spec string) (transport.TPMCloser, error) {
	if spec == "device" {
		return transport.OpenTPM()
	}
	addr, ok := strings.CutPrefix(spec, "tcp:")
	host, port, err := net.SplitHostPort(addr)
	p, perr := strconv.Atoi(port)
	if !ok || err != nil || perr != nil {
		return nil, errors.New("--tpm is device, or tcp:HOST:PORT for a simulator (tests only)")
	}
	t, err := tcp.Open(tcp.Config{CommandAddress: addr, PlatformAddress: net.JoinHostPort(host, strconv.Itoa(p+1))})
	if err != nil {
		return nil, err
	}
	if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(t); err != nil && !errors.Is(err, tpm2.TPMRCInitialize) {
		t.Close()
		return nil, err
	}
	return t, nil
}

// --- the sealed key -------------------------------------------------------------------------------------------------

type sealedKey struct {
	Format  string `json:"format"`
	PCRs    []uint `json:"pcrs"`
	Public  string `json:"public"`
	Private string `json:"private"`
}

func srk(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	return tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(t)
}

func pcrPolicy(t transport.TPM, pcrs []uint, opts ...tpm2.AuthOption) (tpm2.Session, func() error, error) {
	sess, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, nil, err
	}
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
		{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...)}}}
	if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(t); err != nil {
		done()
		return nil, nil, err
	}
	return sess, done, nil
}

// sealKey seals the seed to the PCRs' current values: the sealed file opens only on this TPM, in this boot state.
func sealKey(t transport.TPM, seed []byte, pcrs []uint) (*sealedKey, error) {
	p, err := srk(t)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: p.ObjectHandle}.Execute(t)
	trial, done, err := pcrPolicy(t, pcrs, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	dg, err := tpm2.PolicyGetDigest{PolicySession: trial.Handle()}.Execute(t)
	done()
	if err != nil {
		return nil, err
	}
	got, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: p.ObjectHandle, Name: p.Name},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: seed})}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, NoDA: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: dg.PolicyDigest.Buffer}}),
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	return &sealedKey{Format: sealedFormat, PCRs: pcrs, Public: hex.EncodeToString(tpm2.Marshal(got.OutPublic)),
		Private: hex.EncodeToString(tpm2.Marshal(got.OutPrivate))}, nil
}

// unsealKey opens a sealed key file; the answer travels encrypted under a session salted to the SRK.
func unsealKey(t transport.TPM, s *sealedKey) (ed25519.PrivateKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](unhex(s.Public))
	if err != nil {
		return nil, errors.New("the sealed key file does not read")
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](unhex(s.Private))
	if err != nil {
		return nil, errors.New("the sealed key file does not read")
	}
	p, err := srk(t)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: p.ObjectHandle}.Execute(t)
	obj, err := tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: p.ObjectHandle, Name: p.Name},
		InPrivate: *priv, InPublic: *pub}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the sealed key is not this TPM's: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: obj.ObjectHandle}.Execute(t)
	srkPub, err := p.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	sess, done, err := pcrPolicy(t, s.PCRs)
	if err != nil {
		return nil, err
	}
	defer done()
	out, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name, Auth: sess}}.Execute(t,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(p.ObjectHandle, *srkPub)))
	if err != nil {
		return nil, fmt.Errorf("the TPM does not unseal the key: the machine's boot state (PCRs %v) changed since it "+
			"was sealed; seal the key again from its backup: %w", s.PCRs, err)
	}
	if len(out.OutData.Buffer) != ed25519.SeedSize {
		return nil, errors.New("the sealed key is not an Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(out.OutData.Buffer), nil
}

func readSealed(raw []byte) (*sealedKey, bool) {
	var s sealedKey
	if json.Unmarshal(raw, &s) != nil || s.Format != sealedFormat {
		return nil, false
	}
	return &s, true
}

// --- the counter ----------------------------------------------------------------------------------------------------

type tpmCounter struct {
	t     transport.TPM
	index uint32
	auth  []byte // derived from the key: only the key's holder raises the counter
}

func counterAuth(key crypto.Signer) []byte {
	h := sha256.Sum256(append([]byte("kc-custodian-counter\n"), macKey(key)...))
	return h[:16]
}

// defineCounter creates the NV counter under the owner hierarchy (tpm-init, once per machine).
func defineCounter(t transport.TPM, index uint32, key crypto.Signer) error {
	_, err := tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, Auth: tpm2.TPM2BAuth{Buffer: counterAuth(key)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{NVIndex: tpm2.TPMHandle(index), NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{AuthWrite: true, AuthRead: true, OwnerRead: true, NT: tpm2.TPMNTCounter, NoDA: true},
			DataSize:   8})}.Execute(t)
	return err
}

func (c *tpmCounter) handle() (tpm2.AuthHandle, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(c.index)}.Execute(c.t)
	if err != nil {
		return tpm2.AuthHandle{}, fmt.Errorf("no TPM counter at %#x (run tpm-init): %w", c.index, err)
	}
	return tpm2.AuthHandle{Handle: tpm2.TPMHandle(c.index), Name: pub.NVName, Auth: tpm2.PasswordAuth(c.auth)}, nil
}

// read gives the counter, and false when it was never raised.
func (c *tpmCounter) read() (uint64, bool, error) {
	h, err := c.handle()
	if err != nil {
		return 0, false, err
	}
	got, err := tpm2.NVRead{AuthHandle: h, NVIndex: tpm2.NamedHandle{Handle: h.Handle, Name: h.Name}, Size: 8}.Execute(c.t)
	if errors.Is(err, tpm2.TPMRCNVUninitialized) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return binary.BigEndian.Uint64(got.Data.Buffer), true, nil
}

func (c *tpmCounter) raise() (uint64, error) {
	h, err := c.handle()
	if err != nil {
		return 0, err
	}
	if _, err := (tpm2.NVIncrement{AuthHandle: h, NVIndex: tpm2.NamedHandle{Handle: h.Handle, Name: h.Name}}).Execute(c.t); err != nil {
		return 0, err
	}
	n, _, err := c.read()
	return n, err
}

func parseIndex(s string) (uint32, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 32)
	if err != nil || n < 0x01000000 || n > 0x01FFFFFF {
		return 0, errors.New("--tpm-counter is an NV index in hex, 0x01000000 to 0x01FFFFFF")
	}
	return uint32(n), nil
}

func writeSealed(path string, s *sealedKey) error {
	raw, _ := json.MarshalIndent(s, "", " ")
	if _, err := os.Stat(path); err == nil {
		return errors.New("the sealed key file exists: never overwritten")
	}
	return writeAtomic(path, append(raw, '\n'))
}
