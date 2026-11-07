// SPDX-License-Identifier: EUPL-1.2

//go:build pkcs11

// The PKCS#11 build (decision 0033 point 6, Q9): the records key in a token (YubiHSM 2, or any HSM with CKM_EDDSA),
// dynamically linked because every Go PKCS#11 library needs cgo. The token signs; every signature is verified against
// the key's public half before it leaves, so a module that answers otherwise is never trusted.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	ckmEdDSA      = 0x1057 // PKCS#11 v3.0, not named by the library
	ckkECEdwards  = 0x40
	ckaKeyType    = pkcs11.CKA_KEY_TYPE
	ckaECPoint    = pkcs11.CKA_EC_POINT
	ckoPrivateKey = pkcs11.CKO_PRIVATE_KEY
	ckoPublicKey  = pkcs11.CKO_PUBLIC_KEY
)

type p11Config struct {
	Module  string `json:"module"`   // the module's path (libyubihsm_pkcs11.so, libsofthsm2.so)
	Token   string `json:"token"`    // the token's label
	Key     string `json:"key"`      // the key's label (CKA_LABEL), private and public halves alike
	PinFile string `json:"pin_file"` // the user PIN, in a file of the custodian's own user
}

type p11Key struct {
	mu   sync.Mutex
	ctx  *pkcs11.Ctx
	sess pkcs11.SessionHandle
	obj  pkcs11.ObjectHandle
	pub  ed25519.PublicKey
}

func (k *p11Key) Public() crypto.PublicKey { return k.pub }

func (k *p11Key) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ctx.SignInit(k.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEdDSA, nil)}, k.obj); err != nil {
		return nil, err
	}
	sig, err := k.ctx.Sign(k.sess, msg)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(k.pub, msg, sig) {
		return nil, errors.New("the token's signature does not verify under its public key: refused")
	}
	return sig, nil
}

func (k *p11Key) find(class uint, label string) (pkcs11.ObjectHandle, error) {
	if err := k.ctx.FindObjectsInit(k.sess, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(ckaKeyType, ckkECEdwards)}); err != nil {
		return 0, err
	}
	found, _, err := k.ctx.FindObjects(k.sess, 2)
	_ = k.ctx.FindObjectsFinal(k.sess)
	if err != nil {
		return 0, err
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("%d Ed25519 objects labelled %q in the token: exactly one", len(found), label)
	}
	return found[0], nil
}

// ecPoint reads CKA_EC_POINT: the 32 bytes, raw or as a DER OCTET STRING (04 20 ...), as modules differ.
func ecPoint(v []byte) (ed25519.PublicKey, error) {
	if len(v) == 34 && v[0] == 0x04 && v[1] == 0x20 {
		v = v[2:]
	}
	if len(v) != ed25519.PublicKeySize {
		return nil, errors.New("the token's public key is not an Ed25519 point")
	}
	return ed25519.PublicKey(bytes.Clone(v)), nil
}

func openPKCS11(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg p11Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || cfg.Module == "" || cfg.Token == "" || cfg.Key == "" || cfg.PinFile == "" {
		return nil, errors.New("--pkcs11: {module, token, key, pin_file}, each given")
	}
	if err := keyPerms(cfg.PinFile); err != nil {
		return nil, err
	}
	pin, err := os.ReadFile(cfg.PinFile)
	if err != nil {
		return nil, err
	}
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, fmt.Errorf("the PKCS#11 module %s does not load", cfg.Module)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil || strings.TrimRight(info.Label, " ") != cfg.Token {
			continue
		}
		sess, err := ctx.OpenSession(s, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return nil, err
		}
		if err := ctx.Login(sess, pkcs11.CKU_USER, strings.TrimSpace(string(pin))); err != nil {
			return nil, fmt.Errorf("the token refused the PIN: %w", err)
		}
		k := &p11Key{ctx: ctx, sess: sess}
		if k.obj, err = k.find(ckoPrivateKey, cfg.Key); err != nil {
			return nil, err
		}
		pubObj, err := k.find(ckoPublicKey, cfg.Key)
		if err != nil {
			return nil, err
		}
		attrs, err := ctx.GetAttributeValue(sess, pubObj, []*pkcs11.Attribute{pkcs11.NewAttribute(ckaECPoint, nil)})
		if err != nil || len(attrs) != 1 {
			return nil, errors.New("the token does not give the key's public half")
		}
		if k.pub, err = ecPoint(attrs[0].Value); err != nil {
			return nil, err
		}
		return k, nil
	}
	return nil, fmt.Errorf("no token labelled %q", cfg.Token)
}
