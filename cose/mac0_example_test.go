// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose_test

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func ExampleMac0Message() {
	// load key
	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("our-secret"),
		iana.KeyParameterAlg:        iana.AlgorithmAES_MAC_256_64,
		iana.SymmetricKeyParameterK: key.Base64Bytesify("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"),
	}

	macer, err := k.MACer()
	if err != nil {
		panic(err)
	}

	// create a COSE_Mac0 message
	obj := &cose.Mac0Message[[]byte]{
		Unprotected: cose.Headers{},
		Payload:     []byte("This is the content."),
	}

	// compute MAC
	err = obj.Compute(macer, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Tag: %x\n", obj.Tag())
	// Tag: 726043745027214f

	// encode COSE_Mac0 message
	coseData, err := cbor.Marshal(obj)
	if err != nil {
		panic(err)
	}

	// decode a COSE_Mac0 message
	var obj3 cose.Mac0Message[[]byte]
	cbor.Unmarshal(coseData, &obj3)
	if err != nil {
		panic(err)
	}

	// verify MAC
	err = obj3.Verify(macer, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload: %s\n", string(obj3.Payload))
	// Payload: This is the content.
	fmt.Printf("Tag: %x\n", obj3.Tag())
	// Tag: 726043745027214f

	// or verify and decode a COSE_Mac0 message
	obj2, err := cose.VerifyMac0Message[[]byte](macer, coseData, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload: %s\n", string(obj2.Payload))
	// Payload: This is the content.
	fmt.Printf("Tag: %x\n", obj2.Tag())
	// Tag: 726043745027214f

	// Output:
	// Tag: 726043745027214f
	// Payload: This is the content.
	// Tag: 726043745027214f
	// Payload: This is the content.
	// Tag: 726043745027214f
}
