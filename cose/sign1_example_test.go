// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose_test

import (
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"
)

func ExampleSign1Message() {
	// load Key
	var k key.Key
	err := key.UnmarshalCBOR(key.HexBytesify("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3"), &k)
	if err != nil {
		panic(err)
	}

	// k is:
	// key.Key{
	// 	iana.KeyParameterKty:    iana.KeyTypeEC2,
	// 	iana.KeyParameterKid:    []byte("11"),
	// 	iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
	// 	iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
	// 	iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
	// 	iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	// }

	// create a Sign1Message object.
	obj := &cose.Sign1Message[[]byte]{
		Protected: cose.Headers{
			iana.HeaderParameterAlg: iana.AlgorithmES256,
		},
		Unprotected: cose.Headers{
			iana.HeaderParameterKid: k.Kid(),
		},
		Payload: []byte("This is the content."),
	}

	signer, err := k.Signer()
	if err != nil {
		panic(err)
	}

	externalData := key.HexBytesify("11aa22bb33cc44dd55006699")
	// sign the message
	coseData, err := obj.SignAndEncode(signer, externalData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("COSE(%d bytes): %x...\n", len(coseData), coseData[:32])
	// COSE(98 bytes): d28443a10126a10442313154546869732069732074686520636f6e74656e742e...

	verifier, err := k.Verifier()
	if err != nil {
		panic(err)
	}

	obj2, err := cose.VerifySign1Message[[]byte](verifier, coseData, externalData)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload: %s\n", string(obj2.Payload))
	// Payload: This is the content.

	// verify with a different external data should fail
	obj3, err := cose.VerifySign1Message[[]byte](verifier, coseData, []byte("some other external data."))
	if obj3 != nil {
		panic("should be nil")
	}
	fmt.Println(err)
	// cose/key/ecdsa: Verifier.Verify: invalid signature

	// Output:
	// COSE(98 bytes): d28443a10126a10442313154546869732069732074686520636f6e74656e742e...
	// Payload: This is the content.
	// cose/key/ecdsa: Verifier.Verify: invalid signature
}
