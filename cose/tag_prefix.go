// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

// cwtPrefix represents the fixed prefix of CWT CBOR tag.
// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
var cwtPrefix = []byte{
	0xd8, 0x3d, // #6.61
}

// sign1MessagePrefix represents the fixed prefix of COSE_Sign1_Tagged.
var sign1MessagePrefix = []byte{
	0xd2, // #6.18
	0x84, // array of length 4
}

// signMessagePrefix represents the fixed prefix of COSE_Sign_Tagged.
var signMessagePrefix = []byte{
	0xd8, 0x62, // #6.98
	0x84, // Array of length 4
}

// mac0MessagePrefix represents the fixed prefix of COSE_Mac0_Tagged.
var mac0MessagePrefix = []byte{
	0xd1, // #6.17
	0x84, // array of length 4
}

// macMessagePrefix represents the fixed prefix of COSE_Mac_Tagged.
var macMessagePrefix = []byte{
	0xd8, 0x61, // #6.97
	0x85, // array of length 5
}

// encrypt0MessagePrefix represents the fixed prefix of COSE_Encrypt0_Tagged.
var encrypt0MessagePrefix = []byte{
	0xd0, // #6.16
	0x83, // array of length 3
}

// encryptMessagePrefix represents the fixed prefix of COSE_Encrypt_Tagged.
var encryptMessagePrefix = []byte{
	0xd8, 0x60, // #6.96
	0x83, // array of length 4
}
