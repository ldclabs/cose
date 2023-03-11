// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hkdf implements key derivation function HKDF for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-key-derivation-functions-kd
package hkdf

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF256 derives a key from the given secret, salt, info and key size, using HKDF-SHA-256.
func HKDF256(secret, salt, info []byte, keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), key); err != nil {
		return nil, err
	}
	return key, nil
}

// HKDF512 derives a key from the given secret, salt, info and key size, using HKDF-SHA-512.
func HKDF512(secret, salt, info []byte, keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha512.New, secret, salt, info), key); err != nil {
		return nil, err
	}
	return key, nil
}

// HKDFAES derives a key from the given secret, info and key size.
// The secret should be the AES key, either 16, or 32 bytes to select HKDF-AES-128, or HKDF-AES-256.
func HKDFAES(secret, info []byte, keySize int) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(NewAES(block, info), key); err != nil {
		return nil, err
	}
	return key, nil
}
