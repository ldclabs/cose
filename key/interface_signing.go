// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "bytes"

// Signer is the signing interface for signing objects.
// It is used in COSE_Sign and COSE_Sign1.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signature-algorithms.
type Signer interface {
	// Computes the digital signature for data.
	Sign(data []byte) ([]byte, error)

	// Key returns the private key in the Signer.
	// If the key's "key_ops" field is present, it MUST include "sign":1.
	Key() Key
}

// Verifier is the verifying interface for signing objects.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signature-algorithms.
type Verifier interface {
	// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
	Verify(data, signature []byte) error

	// Key returns the public key in the Verifier.
	// The key returned by this method should not include private key bytes.
	// If the key's "key_ops" field is present, it MUST include "verify":12.
	Key() Key
}

// Signers is a list of signers to be used for signing with one or more signers.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si.
type Signers []Signer

// Lookup returns the Signer for the given key ID.
func (ss Signers) Lookup(kid []byte) Signer {
	for _, s := range ss {
		if bytes.Equal(s.Key().Kid(), kid) {
			return s
		}
	}
	return nil
}

// KeySet returns a set of private keys from the Signers.
func (ss Signers) KeySet() KeySet {
	ks := make(KeySet, len(ss))
	for i, v := range ss {
		ks[i] = v.Key()
	}
	return ks
}

// Verifiers is a list of verifiers to be used for verifying with one or more verifiers.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si.
type Verifiers []Verifier

// Lookup returns the Verifier for the given key ID.
func (vs Verifiers) Lookup(kid []byte) Verifier {
	for _, v := range vs {
		if bytes.Equal(v.Key().Kid(), kid) {
			return v
		}
	}
	return nil
}

// KeySet returns a set of public keys from the Verifiers.
func (vs Verifiers) KeySet() KeySet {
	ks := make(KeySet, len(vs))
	for i, v := range vs {
		ks[i] = v.Key()
	}
	return ks
}
