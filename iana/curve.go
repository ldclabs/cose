// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// IANA-registered COSE elliptic curves.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
// as of 2022-12-19.
const (
	EllipticCurveReserved = 0
	// EC2: NIST P-256 also known as secp256r1
	EllipticCurveP_256 = 1
	// EC2: NIST P-384 also known as secp384r1
	EllipticCurveP_384 = 2
	// EC2: NIST P-521 also known as secp521r1
	EllipticCurveP_521 = 3
	// OKP: X25519 for use w/ ECDH only
	EllipticCurveX25519 = 4
	// OKP: X448 for use w/ ECDH only
	EllipticCurveX448 = 5
	// OKP: Ed25519 for use w/ EdDSA only
	EllipticCurveEd25519 = 6
	// OKP: Ed448 for use w/ EdDSA only
	EllipticCurveEd448 = 7
	// EC2: SECG secp256k1 curve
	EllipticCurveSecp256k1 = 8
)
