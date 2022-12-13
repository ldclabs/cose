// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// MACer is the MAC interface for MAC objects.
//
// Reference https://datatracker.ietf.org/doc/html/rfc8152#section-6
type MACer interface {
	// ComputeMAC computes message authentication code (MAC) for the given data.
	ComputeMAC(data []byte) ([]byte, error)

	// VerifyMAC verifies whether the given MAC is a correct message authentication code (MAC) the given data.
	VerifyMAC(data, mac []byte) error

	// Key returns the key in MACer.
	Key() Key
}
