// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aesgcm implements content encryption algorithm AES-GCM for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for AES-GCM.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/aesgcm: GenerateKey: algorithm mismatch %d`, alg)
	}

	k := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, fmt.Errorf("cose/key/aesgcm: GenerateKey: %w", err)
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: k, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for AES-GCM.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/aesgcm: KeyFrom: algorithm mismatch %d`, alg)
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/key/aesgcm: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid AES-GCM key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeSymmetric {
		return fmt.Errorf(`cose/key/aesgcm: CheckKey: invalid key type, expected "Symmetric", got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.SymmetricKeyParameterK:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmA128GCM, iana.AlgorithmA192GCM, iana.AlgorithmA256GCM:
			// continue
			default:
				return fmt.Errorf(`cose/key/aesgcm: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationEncrypt, iana.KeyOperationDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/key/aesgcm: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/aesgcm: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return fmt.Errorf(`cose/key/aesgcm: CheckKey: invalid parameter k, %v`, err)
	}
	keySize := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/key/aesgcm: CheckKey: invalid parameter k size, expected %d, got %d`, keySize, len(kb))
	}
	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if kid, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/key/aesgcm: CheckKey: invalid parameter kid`)
		}
	}
	return nil
}

type aesGCM struct {
	key   key.Key
	block cipher.Block
}

// New creates a key.Encryptor for the given AES-GCM key.
func New(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(iana.SymmetricKeyParameterK)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return &aesGCM{key: k, block: block}, nil
}

// Encrypt implements the key.Encryptor interface.
// Encrypt encrypts a plaintext with the given iv and additional data.
// It returns the ciphertext or error.
func (h *aesGCM) Encrypt(iv, plaintext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationEncrypt) {
		return nil, fmt.Errorf("cose/key/aesgcm: Encrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/key/aesgcm: Encrypt: invalid nonce size, expected 12, got %d", len(iv))
	}
	aead, err := cipher.NewGCM(h.block)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, iv, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt implements the key.Encryptor interface.
// Decrypt decrypts a ciphertext with the given iv and additional data.
// It returns the corresponding plaintext or error.
func (h *aesGCM) Decrypt(iv, ciphertext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationDecrypt) {
		return nil, fmt.Errorf("cose/key/aesgcm: Decrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/key/aesgcm: Decrypt: invalid nonce size, expected 12, got %d", len(iv))
	}

	aead, err := cipher.NewGCM(h.block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ciphertext, additionalData)
}

// NonceSize implements the key.Encryptor interface.
// NonceSize returns the size of the nonce for encrypting and decrypting.
// It is: 12 bytes.
func (h *aesGCM) NonceSize() int {
	return nonceSize
}

// Key implements the key.Encryptor interface.
// Key returns the key in Encryptor.
func (h *aesGCM) Key() key.Key {
	return h.key
}

const (
	nonceSize = 12
)

func getKeySize(alg key.Alg) (keySize int) {
	switch alg {
	case iana.AlgorithmA128GCM, iana.AlgorithmReserved:
		return 16
	case iana.AlgorithmA192GCM:
		return 24
	case iana.AlgorithmA256GCM:
		return 32
	default:
		return 0
	}
}
