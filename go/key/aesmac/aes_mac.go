// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesmac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new Key with given algorithm for AES-CBC-MAC.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keySize, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesmac: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	kb := key.GetRandomBytes(uint16(keySize))
	_, err := io.ReadFull(rand.Reader, kb)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/aesmac: GenerateKey: %w", err)
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

// KeyFrom returns a Key with given algorithm and bytes for AES-CBC-MAC.
func KeyFrom(alg key.Alg, k []byte) (key.Key, error) {
	keySize, _ := getKeySize(alg)
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/go/key/aesmac: KeyFrom: algorithm mismatch %q`, alg.String())
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/go/key/aesmac: KeyFrom: invalid key size, expected %d, got %d`, keySize, len(k))
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

// CheckKey checks whether the given key is a valid AES-CBC-MAC key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamK:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgAESMAC12864, key.AlgAESMAC25664, key.AlgAESMAC128128, key.AlgAESMAC256128:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/aesmac: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpMACCreate, key.OpMACVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/aesmac: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/aesmac: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(key.ParamK)
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

// NewAESMAC creates a key.MACer for the given AES-CBC-MAC key.
func NewAESMAC(k key.Key) (key.MACer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	cek, _ := k.GetBytes(key.ParamK)
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
	if !h.key.Ops().EmptyOrHas(key.OpMACCreate) {
		return nil, fmt.Errorf("cose/go/key/aesmac: MACCreate: invalid key_ops")
	}

	return h.create(data)
}

// MACVerify implements the key.MACer interface.
// MACVerify verifies whether the given MAC is a correct message authentication code (MAC) the given data.
func (h *aesMAC) MACVerify(data, mac []byte) error {
	if !h.key.Ops().EmptyOrHas(key.OpMACVerify) {
		return fmt.Errorf("cose/go/key/aesmac: MACCreate: invalid key_ops")
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

	ciphertext := append(make([]byte, 0, len(plaintext)+x), plaintext...)
	mode := cipher.NewCBCEncrypter(h.block, fixedIV)
	mode.CryptBlocks(ciphertext, ciphertext)

	tag := make([]byte, h.tagSize)
	copy(tag, ciphertext[len(ciphertext)-aes.BlockSize:]) // last block message
	return tag, nil
}

// Key implements the key.MACer interface.
// Key returns the key in MACer.
func (h *aesMAC) Key() key.Key {
	return h.key
}

func getKeySize(alg key.Alg) (keySize, tagSize int) {
	switch alg {
	case key.AlgAESMAC12864, key.AlgReserved:
		return 16, 8

	case key.AlgAESMAC25664:
		return 32, 8

	case key.AlgAESMAC128128:
		return 16, 16

	case key.AlgAESMAC256128:
		return 32, 16

	default:
		return 0, 0
	}
}
