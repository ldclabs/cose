// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Verifier is the verifying interface for digital signature.
type Verifier interface {
	// Verifies returns nil if signature is a valid signature for data; otherwise returns an error.
	Verify(data, signature []byte) error
}
