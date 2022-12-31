// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aesmac implements message authentication code algorithm AES-CBC-MAC for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti.
package aesmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for AES-CBC-MAC.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesmac: GenerateKey: algorithm mismatch %d`, alg)
	}

	k := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/aesmac: GenerateKey: %w", err)
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: k, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for AES-CBC-MAC.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesmac: KeyFrom: algorithm mismatch %d`, alg)
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/go/key/aesmac: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given key is a valid AES-CBC-MAC key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeSymmetric {
		return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid key type, expected "Symmetric", got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.SymmetricKeyParameterK:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmAES_MAC_128_64, iana.AlgorithmAES_MAC_256_64,
				iana.AlgorithmAES_MAC_128_128, iana.AlgorithmAES_MAC_256_128:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/aesmac: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationMacCreate, iana.KeyOperationMacVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/aesmac: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid parameter k, %v`, err)
	}
	keySize, _ := getKeySize(k.Alg())
	if len(kb) != keySize {
		return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid parameter k`)
	}

	return nil
}

type aesMAC struct {
	key     key.Key
	block   cipher.Block
	tagSize int
}

// New creates a key.MACer for the given AES-CBC-MAC key.
func New(k key.Key) (key.MACer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(iana.SymmetricKeyParameterK)
	_, tagSize := getKeySize(k.Alg())
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return &aesMAC{key: k, tagSize: tagSize, block: block}, nil
}

// MACCreate implements the key.MACer interface.
// MACCreate computes message authentication code (MAC) for the given data.
func (h *aesMAC) MACCreate(data []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationMacCreate) {
		return nil, fmt.Errorf("cose/go/key/aesmac: MACCreate: invalid key_ops")
	}

	return h.create(data)
}

// MACVerify implements the key.MACer interface.
// MACVerify verifies whether the given MAC is a correct message authentication code (MAC) the given data.
func (h *aesMAC) MACVerify(data, mac []byte) error {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationMacVerify) {
		return fmt.Errorf("cose/go/key/aesmac: MACVerify: invalid key_ops")
	}

	expectedMAC, err := h.create(data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expectedMAC, mac) == 1 {
		return nil
	}
	return fmt.Errorf("cose/go/key/aesmac: VerifyMAC: invalid MAC")
}

// the IV is fixed to all zeros
// Reference https://datatracker.ietf.org/doc/html/rfc9053#section-3.2
var fixedIV = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func (h *aesMAC) create(plaintext []byte) ([]byte, error) {
	x := len(plaintext) % aes.BlockSize
	if x > 0 {
		x = aes.BlockSize - x
	}

	ciphertext := make([]byte, len(plaintext)+x)
	copy(ciphertext, plaintext)
	mode := cipher.NewCBCEncrypter(h.block, fixedIV)
	mode.CryptBlocks(ciphertext, ciphertext)

	sum := ciphertext[len(ciphertext)-aes.BlockSize:]
	tag := make([]byte, h.tagSize)
	copy(tag, sum)
	return tag, nil
}

// Key implements the key.MACer interface.
// Key returns the key in MACer.
func (h *aesMAC) Key() key.Key {
	return h.key
}

func getKeySize(alg key.Alg) (keySize, tagSize int) {
	switch alg {
	case iana.AlgorithmAES_MAC_128_64, iana.AlgorithmReserved:
		return 16, 8
	case iana.AlgorithmAES_MAC_256_64:
		return 32, 8
	case iana.AlgorithmAES_MAC_128_128:
		return 16, 16
	case iana.AlgorithmAES_MAC_256_128:
		return 32, 16
	default:
		return 0, 0
	}
}
