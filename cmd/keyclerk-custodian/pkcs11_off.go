// SPDX-License-Identifier: EUPL-1.2

//go:build !pkcs11

package main

import (
	"crypto"
	"errors"
)

func openPKCS11(string) (crypto.Signer, error) {
	return nil, errors.New("this is the static build: a key in a PKCS#11 token needs the pkcs11 build (go build -tags pkcs11)")
}
