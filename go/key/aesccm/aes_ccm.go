// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/pion/dtls/v2/pkg/crypto/ccm"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new Key with given algorithm for AES-CCM.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize, _, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesccm: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	kb := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, kb)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/aesccm: GenerateKey: %w", err)
	}

	idhash := sha1.New()
	idhash.Write(kb)

	return map[key.IntKey]any{
		key.ParamKty: key.KtySymmetric,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: alg,
		key.ParamK:   kb, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for AES-CCM.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize, _, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesccm: KeyFrom: algorithm mismatch %q`, alg.String())
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/go/key/aesccm: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
	}

	idhash := sha1.New()
	idhash.Write(k)

	return map[key.IntKey]any{
		key.ParamKty: key.KtySymmetric,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: alg,
		key.ParamK:   append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid AES-CCM key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-aes-ccm
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/go/key/aesccm: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamK:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgAESCCM1664128, key.AlgAESCCM1664256, key.AlgAESCCM6464128, key.AlgAESCCM6464256,
				key.AlgAESCCM16128128, key.AlgAESCCM16128256, key.AlgAESCCM64128128, key.AlgAESCCM64128256:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/aesccm: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpEncrypt, key.OpDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/aesccm: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/aesccm: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(key.ParamK)
	if err != nil {
		return fmt.Errorf(`cose/go/key/aesccm: CheckKey: invalid parameter k, %v`, err)
	}
	keySize, _, _ := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/go/key/aesccm: CheckKey: invalid parameter k size, expected %d, got %d`, keySize, len(kb))
	}

	return nil
}

type aesCCM struct {
	key    key.Key
	block  cipher.Block
	ivSize int
}

// NewAESCCM creates a key.Encryptor for the given AES-CCM key.
func NewAESCCM(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(key.ParamK)
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
	if !h.key.Ops().EmptyOrHas(key.OpEncrypt) {
		return nil, fmt.Errorf("cose/go/key/aesccm: Encrypt: invalid key_ops")
	}

	_, tagSize, nonceSize := getKeySize(h.key.Alg())
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("cose/go/key/aesccm: Decrypt: invalid nonce size, expected %d, got %d",
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
	if !h.key.Ops().EmptyOrHas(key.OpMACVerify) {
		return nil, fmt.Errorf("cose/go/key/aesccm: Decrypt: invalid key_ops")
	}
	_, tagSize, nonceSize := getKeySize(h.key.Alg())
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("cose/go/key/aesccm: Decrypt: invalid nonce size, expected %d, got %d",
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
	case key.AlgAESCCM1664128, key.AlgReserved:
		return 16, 8, 13
	case key.AlgAESCCM1664256:
		return 32, 8, 13
	case key.AlgAESCCM6464128:
		return 16, 8, 7
	case key.AlgAESCCM6464256:
		return 32, 8, 7
	case key.AlgAESCCM16128128:
		return 16, 16, 13
	case key.AlgAESCCM16128256:
		return 32, 16, 13
	case key.AlgAESCCM64128128:
		return 16, 16, 7
	case key.AlgAESCCM64128256:
		return 32, 16, 7
	default:
		return 0, 0, 0
	}
}
