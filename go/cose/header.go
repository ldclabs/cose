// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import "github.com/ldclabs/cose/go/key"

// COSE Header labels registered in the IANA "COSE Header Parameters" registry.
//
// Reference https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const (
	HeaderLabelReserved          key.IntKey = 0
	HeaderLabelAlgorithm         key.IntKey = 1 // protected header
	HeaderLabelCritical          key.IntKey = 2 // protected header
	HeaderLabelContentType       key.IntKey = 3 // unprotected header
	HeaderLabelKeyID             key.IntKey = 4 // unprotected header
	HeaderLabelIV                key.IntKey = 5 // unprotected header
	HeaderLabelPartialIV         key.IntKey = 6 // unprotected header
	HeaderLabelCounterSignature  key.IntKey = 7 // unprotected header
	HeaderLabelCounterSignature0 key.IntKey = 9 // unprotected header
)

// Headers represents a COSE Generic_Headers structure.
type Headers key.IntMap

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (h Headers) Bytesify() []byte {
	b, _ := key.IntMap(h).MarshalCBOR()
	return b
}

// MarshalCBOR implements the CBOR Marshaler interface for Headers.
// It is the same as IntMap.MarshalCBOR.
func (h Headers) MarshalCBOR() ([]byte, error) {
	return key.IntMap(h).MarshalCBOR()
}
