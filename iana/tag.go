// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// CBOR tag values for COSE structures.
//
// From IANA registry <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
// as of 2022-12-19.
const (
	// COSE Single Recipient Encrypted Data Object
	CBORTagCOSEEncrypt0 = 16
	// COSE Mac w/o Recipients Object
	CBORTagCOSEMac0 = 17
	// COSE Single Signer Data Object
	CBORTagCOSESign1 = 18
	// CBOR Web Token (CWT)
	CBORTagCWT = 61
	// COSE Encrypted Data Object
	CBORTagCOSEEncrypt = 96
	// COSE MACed Data Object
	CBORTagCOSEMac = 97
	// COSE Signed Data Object
	CBORTagCOSESign = 98
)
