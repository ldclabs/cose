// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hmac implements message authentication code algorithm HMAC for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti.
package hmac

import (
	"crypto/hmac"
	"fmt"
	"hash"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

// GenerateKey generates a new Key with given algorithm for HMAC.
func GenerateKey(alg int) (key.Key, error) {
	if alg == iana.AlgorithmReserved {
		alg = iana.AlgorithmHMAC_256_64
	}

	keySize, _ := getKeySize(key.Alg(alg))
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/hmac: GenerateKey: algorithm mismatch %d`, alg)
	}

	k := key.GetRandomBytes(uint16(keySize))
	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: k, // REQUIRED
	}, nil
}

// KeyFrom returns a Key with given algorithm and bytes for HMAC.
func KeyFrom(alg int, k []byte) (key.Key, error) {
	keySize, _ := getKeySize(key.Alg(alg))
	if keySize == 0 {
		return nil, fmt.Errorf(`cose/key/hmac: KeyFrom: algorithm mismatch %d`, alg)
	}
	if keySize != len(k) {
		return nil, fmt.Errorf(`cose/key/hmac: KeyFrom: key length mismatch, expected %d, got %d`,
			keySize, len(k))
	}

	return map[int]any{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.SumKid(k), // default kid, can be set to other value.
		iana.KeyParameterAlg:        alg,
		iana.SymmetricKeyParameterK: append(make([]byte, 0, len(k)), k...), // REQUIRED
	}, nil
}

// CheckKey checks whether the given Key is a valid HMAC key.
func CheckKey(k key.Key) error {
	if k.Kty() != iana.KeyTypeSymmetric {
		return fmt.Errorf(`cose/key/hmac: CheckKey: invalid key type, expected "Symmetric":4, got %d`, k.Kty())
	}

	for p := range k {
		switch p {
		case iana.KeyParameterKty, iana.KeyParameterKid, iana.SymmetricKeyParameterK:
			// continue

		case iana.KeyParameterAlg: // optional
			switch k.Alg() {
			case iana.AlgorithmHMAC_256_64, iana.AlgorithmHMAC_256_256, iana.AlgorithmHMAC_384_384, iana.AlgorithmHMAC_512_512:
			// continue
			default:
				return fmt.Errorf(`cose/key/hmac: CheckKey: algorithm mismatch %d`, k.Alg())
			}

		case iana.KeyParameterKeyOps: // optional
			for _, op := range k.Ops() {
				switch op {
				case iana.KeyOperationMacCreate, iana.KeyOperationMacVerify:
				// continue
				default:
					return fmt.Errorf(`cose/key/hmac: CheckKey: invalid parameter key_ops %d`, op)
				}
			}

		default:
			return fmt.Errorf(`cose/key/hmac: CheckKey: redundant parameter %d`, p)
		}
	}

	// REQUIRED
	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return fmt.Errorf(`cose/key/hmac: CheckKey: invalid parameter k, %v`, err)
	}
	keySize, _ := getKeySize(k.Alg())
	if keySize == 0 {
		return fmt.Errorf(`cose/key/hmac: CheckKey: algorithm mismatch %d`, k.Alg())
	}

	if len(kb) != keySize {
		return fmt.Errorf(`cose/key/hmac: CheckKey: key length mismatch, expected %d, got %d`,
			keySize, len(kb))
	}

	return nil
}

type hMAC struct {
	key     key.Key
	tagSize int
	hash    func() hash.Hash
}

// New creates a key.MACer for the given HMAC key.
func New(k key.Key) (key.MACer, error) {
	if err := CheckKey(k); err != nil {
		return nil, err
	}

	h := k.Alg().HashFunc()
	_, tagSize := getKeySize(k.Alg())

	return &hMAC{key: k, tagSize: tagSize, hash: h.New}, nil
}

// MACCreate implements the key.MACer interface.
// MACCreate computes message authentication code (MAC) for the given data.
func (h *hMAC) MACCreate(data []byte) ([]byte, error) {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationMacCreate) {
		return nil, fmt.Errorf("cose/key/hmac: MACCreate: invalid key_ops")
	}

	return h.create(data)
}

// MACVerify implements the key.MACer interface.
// MACVerify verifies whether the given MAC is a correct message authentication code (MAC) the given data.
func (h *hMAC) MACVerify(data, mac []byte) error {
	if !h.key.Ops().EmptyOrHas(iana.KeyOperationMacVerify) {
		return fmt.Errorf("cose/key/hmac: MACVerify: invalid key_ops")
	}

	expectedMAC, err := h.create(data)
	if err != nil {
		return err
	}
	if hmac.Equal(expectedMAC, mac) {
		return nil
	}
	return fmt.Errorf("cose/key/hmac: VerifyMAC: invalid MAC")
}

func (h *hMAC) create(data []byte) ([]byte, error) {
	cek, err := h.key.GetBytes(iana.SymmetricKeyParameterK)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(h.hash, cek)
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

func getKeySize(alg key.Alg) (keySize, tagSize int) {
	switch alg {
	case iana.AlgorithmHMAC_256_64:
		return 32, 8
	case iana.AlgorithmHMAC_256_256:
		return 32, 32
	case iana.AlgorithmHMAC_384_384:
		return 48, 48
	case iana.AlgorithmHMAC_512_512:
		return 64, 64
	default:
		return 0, 0
	}
}
