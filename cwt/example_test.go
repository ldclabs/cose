// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cwt_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
)

func ExampleClaims() {
	// Create a ed25519 signer key
	privKey, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	signer, err := privKey.Signer()
	if err != nil {
		panic(err)
	}

	// Create a verifier key
	pubKey, err := ed25519.ToPublicKey(privKey)
	if err != nil {
		panic(err)
	}
	verifier, err := pubKey.Verifier()
	if err != nil {
		panic(err)
	}

	// create a claims set
	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "ldc:chain",
		Audience:   "ldc:txpool",
		Expiration: 1670123579,
		CWTID:      []byte{1, 2, 3, 4},
	}

	// sign with Sign1Message
	obj := cose.Sign1Message[cwt.Claims]{Payload: claims}
	cwtData, err := obj.SignAndEncode(signer, nil)
	if err != nil {
		panic(err)
	}

	// decode and verify the cwt
	obj2, err := cose.VerifySign1Message[cwt.Claims](verifier, cwtData, nil)
	if err != nil {
		panic(err)
	}

	// validate the cwt's claims
	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "ldc:txpool",
		ClockSkew:        time.Minute,
	})
	if err != nil {
		panic(err)
	}

	err = validator.Validate(&obj2.Payload)
	fmt.Printf("Validate Claims: %v\n", err)
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired

	cborData, err := key.MarshalCBOR(obj2.Payload)
	// cborData, err := cbor.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(44 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b074401020304

	jsonData, err := json.Marshal(obj2.Payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("JSON(%d bytes): %s\n", len(jsonData), string(jsonData))
	// JSON(87 bytes): {"iss":"ldc:ca","sub":"ldc:chain","aud":"ldc:txpool","exp":1670123579,"cti":"01020304"}

	// Output:
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired
	// CBOR(44 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b074401020304
	// JSON(87 bytes): {"iss":"ldc:ca","sub":"ldc:chain","aud":"ldc:txpool","exp":1670123579,"cti":"01020304"}
}

func ExampleClaimsMap() {
	// Create a ed25519 signer key
	privKey1, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}
	privKey2, err := ecdsa.GenerateKey(key.AlgES256)
	if err != nil {
		panic(err)
	}
	ks := key.KeySet{privKey1, privKey2}

	// create a claims set
	claims := cwt.ClaimsMap{
		cwt.KeyIss:    "ldc:ca",
		cwt.KeySub:    "ldc:chain",
		cwt.KeyAud:    "ldc:txpool",
		cwt.KeyExp:    1670123579,
		key.IntKey(9): "read,write", // The scope of an access token, https://www.iana.org/assignments/cwt/cwt.xhtml.
	}

	// Sign the claims
	signers, err := ks.Signers()
	if err != nil {
		panic(err)
	}
	// sign with SignMessage
	obj := cose.SignMessage[cwt.ClaimsMap]{Payload: claims}
	cwtData, err := obj.SignAndEncode(signers, nil)
	if err != nil {
		panic(err)
	}

	// decode and verify the cwt
	verifiers, err := ks.Verifiers()
	if err != nil {
		panic(err)
	}
	obj2, err := cose.VerifySignMessage[cwt.ClaimsMap](verifiers, cwtData, nil)
	if err != nil {
		panic(err)
	}

	// Validate the claims
	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "ldc:txpool",
		ClockSkew:        time.Minute,
	})
	if err != nil {
		panic(err)
	}

	err = validator.ValidateMap(obj2.Payload)
	fmt.Printf("Validate Claims: %v\n", err)
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired

	cborData, err := key.MarshalCBOR(obj2.Payload)
	// cborData, err := cbor.Marshal(myClaims)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CBOR(%d bytes): %x\n", len(cborData), cborData)
	// CBOR(50 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b096a726561642c7772697465

	jsonData, err := json.Marshal(obj2.Payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("JSON(%d bytes): %s\n", len(jsonData), string(jsonData))
	// JSON(79 bytes): {"1":"ldc:ca","2":"ldc:chain","3":"ldc:txpool","4":1670123579,"9":"read,write"}

	// Output:
	// Validate Claims: cose/go/cwt: Validator.Validate: token has expired
	// CBOR(50 bytes): a501666c64633a636102696c64633a636861696e036a6c64633a7478706f6f6c041a638c103b096a726561642c7772697465
	// JSON(79 bytes): {"1":"ldc:ca","2":"ldc:chain","3":"ldc:txpool","4":1670123579,"9":"read,write"}
}
