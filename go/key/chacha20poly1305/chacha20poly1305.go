// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chacha20poly1305

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new Key with given algorithm for ChaCha20/Poly1305.
func GenerateKey() (key.Key, error) {
	kb := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, kb)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/chacha20poly1305: GenerateKey: %w", err)
	}

	idhash := sha1.New()
	idhash.Write(kb)

	return map[key.IntKey]any{
		key.ParamKty: key.KtySymmetric,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: key.AlgChaCha20Poly1305,
		key.ParamK:   kb, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for ChaCha20/Poly1305.
func KeyFrom(k []byte) (key.Key, error) {
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/go/key/chacha20poly1305: KeyFrom: invalid key size, expected %d, got %d`,
			keySize, len(k))
	}

	idhash := sha1.New()
	idhash.Write(k)

	return map[key.IntKey]any{
		key.ParamKty: key.KtySymmetric,
		key.ParamKid: idhash.Sum(nil)[:10], // default kid, can be set to other value.
		key.ParamAlg: key.AlgChaCha20Poly1305,
		key.ParamK:   append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid ChaCha20/Poly1305 key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-chacha20-and-poly1305
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamK:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgChaCha20Poly1305:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpEncrypt, key.OpDecrypt:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(key.ParamK)
	if err != nil {
		return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: invalid parameter k, %v`, err)
	}
	keySize := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/go/key/chacha20poly1305: CheckKey: invalid parameter k size, expected %d, got %d`,
			keySize, len(kb))
	}

	return nil
}

type chacha struct {
	key key.Key
	cek []byte
}

// New creates a key.Encryptor for the given ChaCha20/Poly1305 key.
func New(k key.Key) (key.Encryptor, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(key.ParamK)
	return &chacha{key: k, cek: cek}, nil
}

// Encrypt implements the key.Encryptor interface.
// Encrypt encrypts a plaintext with the given iv and additional data.
// It returns the ciphertext or error.
func (h *chacha) Encrypt(iv, plaintext, additionalData []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(key.OpEncrypt) {
		return nil, fmt.Errorf("cose/go/key/chacha20poly1305: Encrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/go/key/chacha20poly1305: Encrypt: invalid nonce size, expected 12, got %d", len(iv))
	}
	aead, err := chacha20poly1305.New(h.cek)
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
	if !h.key.Ops().EmptyOrHas(key.OpMACVerify) {
		return nil, fmt.Errorf("cose/go/key/chacha20poly1305: Decrypt: invalid key_ops")
	}

	if len(iv) != nonceSize {
		return nil, fmt.Errorf("cose/go/key/chacha20poly1305: Decrypt: invalid nonce size, expected 12, got %d", len(iv))
	}

	aead, err := chacha20poly1305.New(h.cek)
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

func getKeySize(alg key.Alg) (keySize int) {
	switch alg {
	case key.AlgChaCha20Poly1305, key.AlgReserved:
		return keySize
	default:
		return 0
	}
}