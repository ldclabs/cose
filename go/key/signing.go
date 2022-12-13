// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "bytes"

// Signer is the signing interface for signing objects.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-4
type Signer interface {
	// Computes the digital signature for data.
	Sign(data []byte) ([]byte, error)

	// Key returns the private key in Signer.
	Key() Key
}

// Verifier is the verifying interface for signing objects.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-4
type Verifier interface {
	// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
	Verify(data, signature []byte) error

	// Key returns the public key in Verifier.
	// Security Considerations: The key returned by this method should not include private key bytes.
	Key() Key
}

// Signers is a list of signers to be used for signing with one or more signers.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-4-1
type Signers []Signer

// Verifiers is a list of verifiers to be used for verifying with one or more verifiers.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-4-1
type Verifiers []Verifier

// Lookup returns the verifier for the given key ID.
func (vs Verifiers) Lookup(kid ByteStr) Verifier {
	for _, v := range vs {
		if bytes.Equal(v.Key().Kid(), kid) {
			return v
		}
	}
	return nil
}

// KeySet represents a list of public keys from the Verifiers.
func (vs Verifiers) KeySet() KeySet {
	ks := make(KeySet, len(vs))
	for i, v := range vs {
		ks[i] = v.Key()
	}
	return ks
}
