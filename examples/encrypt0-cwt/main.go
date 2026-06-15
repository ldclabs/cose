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
	symmetricKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("content-key-1"),
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: key.HexBytesify("000102030405060708090a0b0c0d0e0f"),
	}

	encryptor, err := symmetricKey.Encryptor()
	check(err)

	claims := cwt.Claims{
		Issuer:     "ldc:ca",
		Subject:    "encrypted-agent-example",
		Audience:   "agent:runtime",
		Expiration: uint64(time.Now().Add(5 * time.Minute).Unix()),
	}
	externalData := []byte("encrypt0 aad")

	msg := cose.Encrypt0Message[cwt.Claims]{Payload: claims}
	encoded, err := msg.EncryptAndEncode(encryptor, externalData)
	check(err)

	decrypted, err := cose.DecryptEncrypt0Message[cwt.Claims](encryptor, encoded, externalData)
	check(err)

	fmt.Printf("COSE_Encrypt0 CWT decrypted for %q (%d bytes)\n", decrypted.Payload.Subject, len(encoded))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
