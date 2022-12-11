// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Signer is the signing interface for digital signature.
type Signer interface {
	// Computes the digital signature for data.
	Sign(data []byte) ([]byte, error)
}
