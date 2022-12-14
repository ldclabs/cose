// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt

import (
	"bytes"

	"github.com/ldclabs/cose/go/cose"
	"github.com/ldclabs/cose/go/key"
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

// cwtPrefix represents the fixed prefix of CWT CBOR tag.
// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
var cwtPrefix = []byte{
	0xd8, 0x3d, // #6.61
}

// Verify1AndDecode verifies and decodes a CWT in COSE_Sign1 format with a verifier and returns a *Claims.
// externalData should be the same as the one used in Sign1AndEncode.
// It can be nil. https://datatracker.ietf.org/doc/html/rfc9052#section-4-3
func Verify1AndDecode(verifier key.Verifier, coseData, externalData []byte) (*Claims, error) {
	// remove optional CWT CBOR tag
	if bytes.HasPrefix(coseData, cwtPrefix) {
		coseData = coseData[2:]
	}

	s, err := cose.VerifySign1Message(verifier, coseData, externalData)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	if err = key.UnmarshalCBOR(s.Payload, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifyAndDecode verifies and decodes a CWT in COSE_Sign format with some verifiers and returns a *Claims.
// externalData should be the same as the one used in SignAndEncode.
// It can be nil. https://datatracker.ietf.org/doc/html/rfc9052#section-4-3
func VerifyAndDecode(verifiers key.Verifiers, coseData, externalData []byte) (*Claims, error) {
	// remove optional CWT CBOR tag
	if bytes.HasPrefix(coseData, cwtPrefix) {
		coseData = coseData[2:]
	}

	s, err := cose.VerifySignMessage(verifiers, coseData, externalData)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	if err = key.UnmarshalCBOR(s.Payload, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Sign1AndEncode signs and encodes a CWT in COSE_Sign1 format with a signer.
// externalData can be nil. https://datatracker.ietf.org/doc/html/rfc9052#section-4-3
func (claims *Claims) Sign1AndEncode(signer key.Signer, externalData []byte) ([]byte, error) {
	data, err := key.MarshalCBOR(claims)
	if err != nil {
		return nil, err
	}

	s := &cose.Sign1Message{Payload: data}
	return s.SignAndEncode(signer, externalData)
}

// SignAndEncode signs and encodes a CWT in COSE_Sign format with some signers.
// externalData can be nil. https://datatracker.ietf.org/doc/html/rfc9052#section-4-3
func (claims *Claims) SignAndEncode(signers key.Signers, externalData []byte) ([]byte, error) {
	data, err := key.MarshalCBOR(claims)
	if err != nil {
		return nil, err
	}

	s := &cose.SignMessage{Payload: data}
	return s.SignAndEncode(signers, externalData)
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (c *Claims) Bytesify() []byte {
	b, _ := key.MarshalCBOR(c)
	return b
}
