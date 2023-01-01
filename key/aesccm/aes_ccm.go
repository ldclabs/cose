// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aesccm implements content encryption algorithm AES-CCM for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-aes-ccm.
package aesccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/pion/dtls/v2/pkg/crypto/ccm"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for AES-CCM.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize, _, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/aesccm: GenerateKey: algorithm mismatch %d`, alg)
	}

	k := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, fmt.Errorf("cose/key/aesccm: GenerateKey: %w", err)
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: k, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for AES-CCM.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize, _, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/aesccm: KeyFrom: algorithm mismatch %d`, alg)
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/key/aesccm: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid AES-CCM key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeSymmetric {
		return fmt.Errorf(`cose/key/aesccm: CheckKey: invalid key type, expected "Symmetric", got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.SymmetricKeyParameterK:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmAES_CCM_16_64_128, iana.AlgorithmAES_CCM_16_64_256, iana.AlgorithmAES_CCM_64_64_128,
				iana.AlgorithmAES_CCM_64_64_256, iana.AlgorithmAES_CCM_16_128_128, iana.AlgorithmAES_CCM_16_128_256,
				iana.AlgorithmAES_CCM_64_128_128, iana.AlgorithmAES_CCM_64_128_256:
			// continue
			default:
				return fmt.Errorf(`cose/key/aesccm: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationEncrypt, iana.KeyOperationDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/key/aesccm: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/aesccm: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return fmt.Errorf(`cose/key/aesccm: CheckKey: invalid parameter k, %v`, err)
	}
	keySize, _, _ := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/key/aesccm: CheckKey: invalid parameter k size, expected %d, got %d`, keySize, len(kb))
	}
	// RECOMMENDED
	if k.Has(iana.KeyParameterKid) {
		if kid, err := k.GetBytes(iana.KeyParameterKid); err != nil || len(kid) == 0 {
			return fmt.Errorf(`cose/key/aesccm: CheckKey: invalid parameter kid`)
		}
	}
	return nil
}

type aesCCM struct {
	key    key.Key
	block  cipher.Block
	ivSize int
}

// New creates a key.Encryptor for the given AES-CCM key.
func New(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(iana.SymmetricKeyParameterK)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	_, _, nonceSize := getKeySize(k.Alg())
	return &aesCCM{key: k, block: block, ivSize: nonceSize}, nil
}

// Encrypt implements the key.Encryptor interface.
// Encrypt encrypts a plaintext with the given iv and additional data.
// It returns the ciphertext or error.
func (h *aesCCM) Encrypt(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationEncrypt) {
		return nil, fmt.Errorf("cose/key/aesccm: Encrypt: invalid key_ops")
	}

	_, tagSize, nonceSize := getKeySize(h.key.Alg())
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("cose/key/aesccm: Encrypt: invalid nonce size, expected %d, got %d",
			nonceSize, len(nonce))
	}
	aead, err := ccm.NewCCM(h.block, tagSize, nonceSize)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt implements the key.Encryptor interface.
// Decrypt decrypts a ciphertext with the given iv and additional data.
// It returns the corresponding plaintext or error.
func (h *aesCCM) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationDecrypt) {
		return nil, fmt.Errorf("cose/key/aesccm: Decrypt: invalid key_ops")
	}
	_, tagSize, nonceSize := getKeySize(h.key.Alg())
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("cose/key/aesccm: Decrypt: invalid nonce size, expected %d, got %d",
			nonceSize, len(nonce))
	}

	aead, err := ccm.NewCCM(h.block, tagSize, nonceSize)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

// NonceSize implements the key.Encryptor interface.
// NonceSize returns the size of the nonce for encrypting and decrypting.
// It is: 7 bytes or 13 bytes.
func (h *aesCCM) NonceSize() int {
	return h.ivSize
}

// Key implements the key.Encryptor interface.
// Key returns the key in Encryptor.
func (h *aesCCM) Key() key.Key {
	return h.key
}

func getKeySize(alg key.Alg) (keySize, tagSize, nonceSize int) {
	switch alg {
	case iana.AlgorithmAES_CCM_16_64_128, iana.AlgorithmReserved:
		return 16, 8, 13
	case iana.AlgorithmAES_CCM_16_64_256:
		return 32, 8, 13
	case iana.AlgorithmAES_CCM_64_64_128:
		return 16, 8, 7
	case iana.AlgorithmAES_CCM_64_64_256:
		return 32, 8, 7
	case iana.AlgorithmAES_CCM_16_128_128:
		return 16, 16, 13
	case iana.AlgorithmAES_CCM_16_128_256:
		return 32, 16, 13
	case iana.AlgorithmAES_CCM_64_128_128:
		return 16, 16, 7
	case iana.AlgorithmAES_CCM_64_128_256:
		return 32, 16, 7
	default:
		return 0, 0, 0
	}
}
