// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/all"
)

func main() {
	privateKey := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    []byte("detached-signer"),
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.HexBytesify("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
	}

	signer, err := privateKey.Signer()
	check(err)
	verifier, err := privateKey.Verifier()
	check(err)

	payload := []byte("payload transported outside the COSE object")
	externalData := []byte("detached aad")

	msg := cose.Sign1Message[[]byte]{Payload: payload}
	encoded, err := msg.SignDetachedAndEncode(signer, externalData)
	check(err)

	verified, err := cose.VerifySign1MessageDetached[[]byte](verifier, encoded, payload, externalData)
	check(err)

	fmt.Printf("detached COSE_Sign1 verified %d payload bytes with %d COSE bytes\n",
		len(verified.Payload), len(encoded))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
