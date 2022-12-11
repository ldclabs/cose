// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"
	"io"

	"github.com/ldclabs/cose/go/key"
)

func GenerateKey(alg key.Alg) (key.Key, error) {
	keyLen, _ := getKeyLen(alg)
	if keyLen == 0 {
		return nil, fmt.Errorf(`cose/key/hmac: GenerateKey: algorithm mismatch %q`, alg.String())
	}

	kb := make([]byte, keyLen)
	_, err := io.ReadFull(rand.Reader, kb)
	// TODO derive key
	if err != nil {
		return nil, fmt.Errorf("cose/key/hmac: GenerateKey: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc9053#name-double-coordinate-curves
	return map[key.IntKey]any{
		key.ParamKty: key.KtySymmetric,
		key.ParamAlg: alg,
		key.ParamK:   kb, // REQUIRED
	}, nil
}

// https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti
func CheckKey(k key.Key) error {
	if k.Kty() != key.KtySymmetric {
		return fmt.Errorf(`cose/key/hmac: CheckKey: invalid key type, expected "Symmetric", got %q`, k.Kty().String())
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
				return fmt.Errorf(`cose/key/hmac: CheckKey: algorithm mismatch %q`, k.Alg().String())
			}

		case key.ParamOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case key.OpMacCreate, key.OpMacVerify:
				// continue
				default:
					return fmt.Errorf(`cose/key/hmac: CheckKey: invalid parameter key_ops %q`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/hmac: CheckKey: redundant parameter %q`, k.ParamString(p))
		}
	}

	// REQUIRED
	kb, ok := k.GetBstr(key.ParamK)
	keyLen, _ := getKeyLen(k.Alg())
	if ok && len(kb) != keyLen {
		return fmt.Errorf(`cose/key/hmac: CheckKey: invalid parameter k`)
	}

	return nil
}

type HMAC struct {
	key     key.Key
	tagSize int
	k       []byte
	h       func() hash.Hash
}

func NewSigner(k key.Key) (key.Signer, error) {
	return NewHMAC(k)
}

func NewVerifier(k key.Key) (key.Verifier, error) {
	return NewHMAC(k)
}

func NewHMAC(k key.Key) (*HMAC, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	kb, ok := k.GetBstr(key.ParamK)
	if !ok {
		return nil, fmt.Errorf("cose/key/HMAC: NewHMAC: invalid key")
	}

	h := k.Alg().HashFunc()
	if !h.Available() {
		return nil, fmt.Errorf("cose/key/HMAC: NewHMAC: hash function is not available")
	}
	_, tagSize := getKeyLen(k.Alg())

	return &HMAC{key: k, tagSize: tagSize, k: kb, h: h.New}, nil
}

// Sign computes message authentication code (MAC) for the given data.
func (h *HMAC) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(h.h, h.k)
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	tag := mac.Sum(nil)
	return tag[:h.tagSize], nil
}

// Verify verifies whether the given MAC is a correct message authentication
// code (MAC) the given data.
func (h *HMAC) Verify(data, mac []byte) error {
	expectedMAC, err := h.Sign(data)
	if err != nil {
		return err
	}
	if hmac.Equal(expectedMAC, mac) {
		return nil
	}
	return fmt.Errorf("cose/key/HMAC: VerifyMAC: invalid MAC")
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
