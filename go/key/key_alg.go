// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"crypto"
	"errors"
	"strconv"
)

// Algorithms supported by this library.
// # See Also
// https://datatracker.ietf.org/doc/html/rfc9053
const (
	AlgReserved Alg = 0

	// ECDSA P-256 w/ SHA-256.
	AlgES256 Alg = -7
	// ECDSA P-384 w/ SHA-384.
	AlgES384 Alg = -35
	// ECDSA P-521 w/ SHA-512.
	AlgES512 Alg = -36

	// PureEdDSA.
	AlgEdDSA Alg = -8

	// HMAC w/ SHA-256 truncated to 64 bits
	AlgHMAC25664 Alg = 4
	// HMAC w/ SHA-256
	AlgHMAC256256 Alg = 5
	// HMAC w/ SHA-384
	AlgHMAC384384 Alg = 6
	// HMAC w/ SHA-512
	AlgHMAC512512 Alg = 7
)

// Algorithm represents an IANA algorithm entry in the COSE Algorithms registry.
// Algorithms with string values are not supported.
//
// # See Also
//
// COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
type Alg int

// String returns the name of the algorithm
func (a Alg) String() string {
	switch a {
	case AlgES256:
		return "ES256"
	case AlgES384:
		return "ES384"
	case AlgES512:
		return "ES512"

	case AlgEdDSA:
		// As stated in RFC 8152 8.2, only the pure EdDSA version is used for åCOSE.
		return "EdDSA"

	case AlgHMAC25664:
		return "HMAC 256/64"
	case AlgHMAC256256:
		return "HMAC 256/256"
	case AlgHMAC384384:
		return "HMAC 384/384"
	case AlgHMAC512512:
		return "HMAC 512/512"

	default:
		return "UnsupportedAlg(" + strconv.Itoa(int(a)) + ")"
	}
}

// HashFunc returns the hash associated with the algorithm supported.
func (a Alg) HashFunc() crypto.Hash {
	switch a {
	case AlgES256, AlgHMAC25664, AlgHMAC256256:
		return crypto.SHA256
	case AlgES384, AlgHMAC384384:
		return crypto.SHA384
	case AlgES512, AlgHMAC512512:
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
