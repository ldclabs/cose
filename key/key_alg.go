// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"crypto"
	"errors"

	"github.com/ldclabs/cose/iana"
)

// Algorithm represents an IANA algorithm entry in the COSE Algorithms registry.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#algorithms
type Alg int

// HashFunc returns the hash associated with the algorithm supported.
func (a Alg) HashFunc() crypto.Hash {
	switch a {
	case iana.AlgorithmES256, iana.AlgorithmHMAC_256_64, iana.AlgorithmHMAC_256_256:
		return crypto.SHA256
	case iana.AlgorithmES384, iana.AlgorithmHMAC_384_384:
		return crypto.SHA384
	case iana.AlgorithmES512, iana.AlgorithmHMAC_512_512:
		return crypto.SHA512
	default:
		return 0
	}
}

// ComputeHash computes a hash of the given data using the given hash.
func ComputeHash(h crypto.Hash, data []byte) ([]byte, error) {
	if !h.Available() {
		return nil, errors.New("hash function is not available")
	}

	hh := h.New()
	if _, err := hh.Write(data); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}