// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"github.com/ldclabs/cose/key"
)

// Claims is a set of simple claims for CWT.
type Claims struct {
	Issuer     string      `cbor:"1,keyasint,omitempty" json:"iss,omitempty"`
	Subject    string      `cbor:"2,keyasint,omitempty" json:"sub,omitempty"`
	Audience   string      `cbor:"3,keyasint,omitempty" json:"aud,omitempty"`
	Expiration uint64      `cbor:"4,keyasint,omitempty" json:"exp,omitempty"` // seconds since epoch
	NotBefore  uint64      `cbor:"5,keyasint,omitempty" json:"nbf,omitempty"` // seconds since epoch
	IssuedAt   uint64      `cbor:"6,keyasint,omitempty" json:"iat,omitempty"` // seconds since epoch
	CWTID      key.ByteStr `cbor:"7,keyasint,omitempty" json:"cti,omitempty"`
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (c *Claims) Bytesify() []byte {
	b, _ := key.MarshalCBOR(c)
	return b
}
