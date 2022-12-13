// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "strconv"

// Crv represents the key's curve.
type Crv int

// Reference https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
const (
	CrvReserved  Crv = 0
	CrvP256      Crv = 1
	CrvP384      Crv = 2
	CrvP521      Crv = 3
	CrvX25519    Crv = 4
	CrvX448      Crv = 5
	CrvEd25519   Crv = 6
	CrvEd448     Crv = 7
	CrvSecp256k1 Crv = 8
)

// Alg returns the algorithm that matched the key's curve.
func (c Crv) Alg() Alg {
	switch c {
	case CrvP256:
		return AlgES256
	case CrvP384:
		return AlgES384
	case CrvP521:
		return AlgES512
	case CrvEd25519:
		return AlgEdDSA
	case CrvEd448:
		return AlgEdDSA
	case CrvSecp256k1:
		return AlgES256K
	default:
		return AlgReserved
	}
}

// String returns the name of the key's curve.
func (c Crv) String() string {
	switch c {
	case CrvP256:
		return "P-256"
	case CrvP384:
		return "P-384"
	case CrvP521:
		return "P-521"
	case CrvX25519:
		return "X25519"
	case CrvX448:
		return "X448"
	case CrvEd25519:
		return "Ed25519"
	case CrvEd448:
		return "Ed448"
	case CrvSecp256k1:
		return "secp256k1"
	case CrvReserved:
		return "Reserved"
	default:
		return "UnassignedCrv(" + strconv.Itoa(int(c)) + ")"
	}
}
