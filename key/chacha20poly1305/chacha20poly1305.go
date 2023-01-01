// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chacha20poly1305 implements content encryption algorithm ChaCha20/Poly1305 for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-chacha20-and-poly1305.
package chacha20poly1305

import (
	"fmt"

	gochacha20poly1305 "golang.org/x/crypto/chacha20poly1305"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for ChaCha20/Poly1305.
func GenerateKey() (key.Key, error) {
	k := key.GetRandomBytes(uint16(keySize))
	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: k, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for ChaCha20/Poly1305.
func KeyFrom(k []byte) (key.Key, error) {
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/key/chacha20poly1305: KeyFrom: invalid key size, expected %d, got %d`,
			keySize, len(k))
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        iana.AlgorithmChaCha20Poly1305,
		iana.SymmetricKeyParameterK: append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid ChaCha20/Poly1305 key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeSymmetric {
		return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: invalid key type, expected "Symmetric":4, got %d`,
			k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.SymmetricKeyParameterK:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmChaCha20Poly1305:
			// continue
			default:
				return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationEncrypt, iana.KeyOperationDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: invalid parameter key_ops %d`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: invalid parameter k, %w`, err)
	}

	keySize := getKeySize(k.Alg())
	if keySize == 0 {
		return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: algorithm mismatch %d`, k.Alg())
	}
	if len(kb) != keySize {
		return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: invalid key size, expected %d, got %d`,
			keySize, len(kb))
	}

	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if kid, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/key/chacha20poly1305: CheckKey: invalid parameter kid`)
		}
	}
	return nil
}

type chacha struct {
	key key.Key
}

// New creates a key.Encryptor for the given ChaCha20/Poly1305 key.
func New(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	return &chacha{key: k}, nil
}

// Encrypt implements the key.Encryptor interface.
// Encrypt encrypts a plaintext with the given iv and additional data.
// It returns the ciphertext or error.
func (h *chacha) Encrypt(iv, plaintext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationEncrypt) {
		return nil, fmt.Errorf("cose/key/chacha20poly1305: Encryptor.Encrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/key/chacha20poly1305: Encryptor.Encrypt: invalid nonce size, expected 12, got %d",
			len(iv))
	}
	cek, _ := h.key.GetBytes(iana.SymmetricKeyParameterK)
	aead, err := gochacha20poly1305.New(cek)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, iv, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt implements the key.Encryptor interface.
// Decrypt decrypts a ciphertext with the given iv and additional data.
// It returns the corresponding plaintext or error.
func (h *chacha) Decrypt(iv, ciphertext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationDecrypt) {
		return nil, fmt.Errorf("cose/key/chacha20poly1305: Encryptor.Decrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/key/chacha20poly1305: Encryptor.Decrypt: invalid nonce size, expected 12, got %d",
			len(iv))
	}

	cek, _ := h.key.GetBytes(iana.SymmetricKeyParameterK)
	aead, err := gochacha20poly1305.New(cek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ciphertext, additionalData)
}

// NonceSize implements the key.Encryptor interface.
// NonceSize returns the size of the nonce for encrypting and decrypting.
// It is: 12 bytes.
func (h *chacha) NonceSize() int {
	return nonceSize
}

// Key implements the key.Encryptor interface.
// Key returns the key in Encryptor.
func (h *chacha) Key() key.Key {
	return h.key
}

const (
	keySize   = 32
	nonceSize = 12
)

func getKeySize(alg key.Alg) int {
	switch alg {
	case iana.AlgorithmChaCha20Poly1305:
		return keySize
	default:
		return 0
	}
}
