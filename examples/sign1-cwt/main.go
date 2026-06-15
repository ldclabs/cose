// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"fmt"
	"time"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/cwt"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/all"
)

func main() {
	privateKey := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    []byte("signer-1"),
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.HexBytesify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
	}

	signer, err := privateKey.Signer()
	check(err)
	verifier, err := privateKey.Verifier()
	check(err)

	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "agent:example",
		Audience:   "agent:runtime",
		Expiration: uint64(time.Now().Add(5 * time.Minute).Unix()),
		CWTID:      []byte{1, 2, 3, 4},
	}
	externalData := []byte("example aad")

	msg := cose.Sign1Message[cwt.Claims]{Payload: claims}
	encoded, err := msg.SignAndEncode(signer, externalData)
	check(err)

	verified, err := cose.VerifySign1Message[cwt.Claims](verifier, encoded, externalData)
	check(err)

	validator, err := cwt.NewValidator(&cwt.ValidatorOpts{
		ExpectedIssuer:   "ldc:ca",
		ExpectedAudience: "agent:runtime",
		ClockSkew:        time.Minute,
	})
	check(err)
	check(validator.Validate(&verified.Payload))

	fmt.Printf("COSE_Sign1 CWT verified for %q (%d bytes)\n", verified.Payload.Subject, len(encoded))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
