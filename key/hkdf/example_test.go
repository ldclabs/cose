// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hkdf_test

import (
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"

	"github.com/ldclabs/cose/key/hkdf"
)

func ExampleHKDF256() {
	// Create a KDF Context
	kdfContext := cose.KDFContext{
		AlgorithmID: iana.AlgorithmA128GCM,
		SuppPubInfo: cose.SuppPubInfo{
			KeyDataLength: 128,
			Protected: cose.Headers{
				iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256,
			},
		},
	}
	ctxData, err := key.MarshalCBOR(kdfContext)
	if err != nil {
		panic(err)
	}

	// Derive a key
	secret := key.HexBytesify("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6")
	k, err := hkdf.HKDF256(secret, nil, ctxData, 128/8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("key: %X\n", k)
	// key: 56074D506729CA40C4B4FE50C6439893

	// Output:
	// key: 56074D506729CA40C4B4FE50C6439893
}

func ExampleHKDFAES() {
	// Create a KDF Context
	kdfContext := cose.KDFContext{
		AlgorithmID: iana.AlgorithmAES_CCM_16_64_128,
		SuppPubInfo: cose.SuppPubInfo{
			KeyDataLength: 128,
			Protected: cose.Headers{
				iana.HeaderParameterAlg: iana.AlgorithmDirect_HKDF_AES_128,
			},
		},
	}
	ctxData, err := key.MarshalCBOR(kdfContext)
	if err != nil {
		panic(err)
	}

	// Derive a key
	secret := key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbg")
	k, err := hkdf.HKDFAES(secret, ctxData, 128/8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("key: %X\n", k)
	// key: F0CCBAF836D73DA63ED8508EF966EEC9

	// Output:
	// key: F0CCBAF836D73DA63ED8508EF966EEC9
}
