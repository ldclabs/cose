// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose_test

import (
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func ExampleEncrypt0Message() {
	// load key
	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("our-secret2"),
		iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
		iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXhkV8FJG-Onbc6mxCcY"),
	}

	encryptor, err := k.Encryptor()
	if err != nil {
		panic(err)
	}

	// create a claim set
	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "ldc:chain",
		Audience:   "ldc:txpool",
		Expiration: 1670123579,
		CWTID:      []byte{1, 2, 3, 4},
	}

	// create a COSE_Encrypt0 message
	obj := &cose.Encrypt0Message[cwt.Claims]{
		Payload: claims,
	}

	// encrypt and encode COSE_Encrypt0 message
	cwtData, err := obj.EncryptAndEncode(encryptor, []byte("some external data."))
	if err != nil {
		panic(err)
	}

	// will generate a random IV for each encryption when not set.
	// iv, _ := obj.Unprotected.GetBytes(iana.HeaderParameterIV)
	// fmt.Printf("IV: %x\n", iv)
	// IV: ab1ec0651cc7878ab5410eb366

	fmt.Printf("CWT(%d bytes): %x...\n", len(cwtData), cwtData[:20])
	// CWT(89 bytes): d08343a1010aa2044b6f75722d73656372657432...

	obj2, err := cose.DecryptEncrypt0Message[cwt.Claims](encryptor, cwtData, []byte("some external data."))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload: %#v\n", obj2.Payload)
	// Payload: cwt.Claims{Issuer:"ldc:ca", Subject:"ldc:chain", Audience:"ldc:txpool", Expiration:0x638c103b, NotBefore:0x0, IssuedAt:0x0, CWTID:key.ByteStr{0x1, 0x2, 0x3, 0x4}}

	// Output:
	// CWT(89 bytes): d08343a1010aa2044b6f75722d73656372657432...
	// Payload: cwt.Claims{Issuer:"ldc:ca", Subject:"ldc:chain", Audience:"ldc:txpool", Expiration:0x638c103b, NotBefore:0x0, IssuedAt:0x0, CWTID:key.ByteStr{0x1, 0x2, 0x3, 0x4}}
}
