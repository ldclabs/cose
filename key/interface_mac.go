// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// MACer is the MAC interface for MAC objects.
// It is used in COSE_Mac and COSE_Mac0.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-message-authentication-code.
type MACer interface {
	// MACCreate computes message authentication code (MAC) for the given data.
	MACCreate(data []byte) ([]byte, error)

	// MACVerify verifies whether the given MAC is a correct message authentication code (MAC) for the given data.
	MACVerify(data, mac []byte) error

	// Key returns the key in the MACer.
	// If the key's "key_ops" field is present, it MUST include "MAC create":9 when creating an HMAC authentication tag.
	// If the key's "key_ops" field is present, it MUST include "MAC verify":10 when verifying an HMAC authentication tag.
	Key() Key
}
