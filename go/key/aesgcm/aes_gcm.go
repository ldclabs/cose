// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new Key with given algorithm for AES-GCM.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesgcm: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	kb := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, kb)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/aesgcm: GenerateKey: %w", err)
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

// KeyFrom returns a Key with given algorithm and bytes for AES-GCM.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesgcm: KeyFrom: algorithm mismatch %q`, alg.String())
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/go/key/aesgcm: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
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

// CheckKey checks whether the given key is a valid AES-GCM key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamK:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgA128GCM, key.AlgA192GCM, key.AlgA256GCM:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpEncrypt, key.OpDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(key.ParamK)
	if err != nil {
		return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: invalid parameter k, %v`, err)
	}
	keySize := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/go/key/aesgcm: CheckKey: invalid parameter k size, expected %d, got %d`, keySize, len(kb))
	}

	return nil
}

type aesGCM struct {
	key   key.Key
	block cipher.Block
}

// NewAESGCM creates a key.Encryptor for the given AES-GCM key.
func NewAESGCM(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(key.ParamK)
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
	if !h.key.Ops().EmptyOrHas(key.OpEncrypt) {
		return nil, fmt.Errorf("cose/go/key/aesgcm: Encrypt: invalid key_ops")
	}

	if len(iv) != 12 {
		return nil, fmt.Errorf("cose/go/key/aesgcm: Encrypt: invalid nonce size, expected 12, got %d", len(iv))
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
	if !h.key.Ops().EmptyOrHas(key.OpMACVerify) {
		return nil, fmt.Errorf("cose/go/key/aesgcm: Decrypt: invalid key_ops")
	}

	if len(iv) != 12 {
		return nil, fmt.Errorf("cose/go/key/aesgcm: Decrypt: invalid nonce size, expected 12, got %d", len(iv))
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
	return 12
}

// Key implements the key.Encryptor interface.
// Key returns the key in Encryptor.
func (h *aesGCM) Key() key.Key {
	return h.key
}

func getKeySize(alg key.Alg) (keySize int) {
	switch alg {
	case key.AlgA128GCM, key.AlgReserved:
		return 16
	case key.AlgA192GCM:
		return 24
	case key.AlgA256GCM:
		return 32
	default:
		return 0
	}
}
