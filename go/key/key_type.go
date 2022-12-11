// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "strconv"

type Kty int

// https://www.iana.org/assignments/cose/cose.xhtml#key-type
const (
	KtyReserved  Kty = 0
	KtyOKP       Kty = 1
	KtyEC2       Kty = 2
	KtyRSA       Kty = 3
	KtySymmetric Kty = 4
	KtyHSSLMS    Kty = 5 // https://datatracker.ietf.org/doc/html/rfc8778
	KtyWalnutDSA Kty = 6 // https://datatracker.ietf.org/doc/html/rfc9021
)

// String returns the name of the key type
func (k Kty) String() string {
	switch k {
	case KtyOKP:
		return "OKP"
	case KtyEC2:
		return "EC2"
	case KtyRSA:
		return "RSA"
	case KtySymmetric:
		return "Symmetric"
	case KtyHSSLMS:
		return "HSS/LMS"
	case KtyWalnutDSA:
		return "WalnutDSA"
	case KtyReserved:
		return "Reserved"
	default:
		return "UnassignedKty(" + strconv.Itoa(int(k)) + ")"
	}
}
