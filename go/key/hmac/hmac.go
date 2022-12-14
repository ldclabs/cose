// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	gohmac "crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"

	"github.com/ldclabs/cose/go/key"
)

// GenerateKey generates a new key with given algorithm for HMAC.
func GenerateKey(alg key.Alg) (key.Key, error) {
	keyLen, _ := getKeyLen(alg)
	if keyLen == 0 {
		return nil, fmt.Errorf(`cose/go/key/hmac: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	kb := key.GetRandomBytes(uint16(keyLen))
	_, err := io.ReadFull(rand.Reader, kb)
	if err != nil {
		return nil, fmt.Errorf("cose/go/key/hmac: GenerateKey: %w", err)
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

// CheckKey checks whether the given key is a valid HMAC key.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/go/key/hmac: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
	}

	for p := range k {
		switch p {
		case key.ParamKty, key.ParamKid, key.ParamK:
			// continue

		case key.ParamAlg: // optional
			switch k.Alg() {
			case key.AlgHMAC25664, key.AlgHMAC256256, key.AlgHMAC384384, key.AlgHMAC512512:
			// continue
			default:
				return fmt.Errorf(`cose/go/key/hmac: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpMACCreate, key.OpMACVerify:
				// continue
				default:
					return fmt.Errorf(`cose/go/key/hmac: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/go/key/hmac: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(key.ParamK)
	if err != nil {
		return fmt.Errorf(`cose/go/key/hmac: CheckKey: invalid parameter k, %v`, err)
	}
	keyLen, _ := getKeyLen(k.Alg())
	if len(kb) != keyLen {
		return fmt.Errorf(`cose/go/key/hmac: CheckKey: invalid parameter k`)
	}

	return nil
}

type hMAC struct {
	key     key.Key
	tagSize int
	k       []byte
	h       func() hash.Hash
}

// NewHMAC creates a key.MACer for the given HMAC key.
func NewHMAC(k key.Key) (key.MACer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	kb, _ := k.GetBytes(key.ParamK)
	h := k.Alg().HashFunc()
	if !h.Available() {
		return nil, fmt.Errorf("cose/go/key/hmac: NewHMAC: hash function is not available")
	}
	_, tagSize := getKeyLen(k.Alg())

	return &hMAC{key: k, tagSize: tagSize, k: kb, h: h.New}, nil
}

// MACCreate implements the key.MACer interface.
// MACCreate computes message authentication code (MAC) for the given data.
func (h *hMAC) MACCreate(data []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(key.OpMACCreate) {
		return nil, fmt.Errorf("cose/go/key/hmac: MACCreate: invalid key_ops")
	}

	return h.create(data)
}

// MACVerify implements the key.MACer interface.
// MACVerify verifies whether the given MAC is a correct message authentication code (MAC) the given data.
func (h *hMAC) MACVerify(data, mac []byte) error {
	if !h.key.Ops().EmptyOrHas(key.OpMACVerify) {
		return fmt.Errorf("cose/go/key/hmac: MACCreate: invalid key_ops")
	}

	expectedMAC, err := h.create(data)
	if err != nil {
		return err
	}
	if gohmac.Equal(expectedMAC, mac) {
		return nil
	}
	return fmt.Errorf("cose/go/key/hmac: VerifyMAC: invalid MAC")
}

func (h *hMAC) create(data []byte) ([]byte, error) {
	mac := gohmac.New(h.h, h.k)
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	tag := mac.Sum(nil)
	return tag[:h.tagSize], nil
}

// Key implements the key.MACer interface.
// Key returns the key in MACer.
func (h *hMAC) Key() key.Key {
	return h.key
}

func getKeyLen(alg key.Alg) (keyLen, tagSize int) {
	switch alg {
	case key.AlgHMAC25664, key.AlgReserved:
		return 32, 8

	case key.AlgHMAC256256:
		return 32, 32

	case key.AlgHMAC384384:
		return 48, 48

	case key.AlgHMAC512512:
		return 64, 64

	default:
		return 0, 0
	}
}
