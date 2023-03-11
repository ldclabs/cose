// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose_test

import (
	"fmt"

	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/aesgcm"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/hkdf"
)

func ExampleEncryptMessage() {
	keyR := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("meriadoc.brandybuck@buckland.example"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.Base64Bytesify("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"),
		iana.EC2KeyParameterY:   key.Base64Bytesify("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"),
		iana.EC2KeyParameterD:   key.Base64Bytesify("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"),
	}

	keyS := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("meriadoc.brandybuck@buckland.example"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.Base64Bytesify("mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA"),
		iana.EC2KeyParameterY:   key.Base64Bytesify("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"),
	}

	ecdher, err := ecdh.NewECDHer(keyR)
	if err != nil {
		panic(err)
	}

	// shared secret by ECDH-ES
	secret, err := ecdher.ECDH(keyS)
	if err != nil {
		panic(err)
	}

	// derive the key from the shared secret
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
	cek, err := hkdf.HKDF256(secret, nil, ctxData, 128/8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Derived key: %X\n", cek)
	// Derived key: 56074D506729CA40C4B4FE50C6439893

	gcmkey, err := aesgcm.KeyFrom(iana.AlgorithmA128GCM, cek)
	if err != nil {
		panic(err)
	}

	encryptor, err := gcmkey.Encryptor()
	if err != nil {
		panic(err)
	}

	obj := &cose.EncryptMessage[[]byte]{
		Payload: []byte("Encryption example for spec - Direct ECDH"),
	}

	err = obj.Encrypt(encryptor, nil)
	if err != nil {
		panic(err)
	}

	ck, err := ecdsa.ToCompressedKey(keyS)
	if err != nil {
		panic(err)
	}
	rp := &cose.Recipient{
		Protected: cose.Headers{iana.HeaderParameterAlg: iana.AlgorithmECDH_ES_HKDF_256},
		Unprotected: cose.Headers{
			iana.HeaderAlgorithmParameterEphemeralKey: ck,
			iana.HeaderParameterKid:                   []byte("meriadoc.brandybuck@buckland.example"),
		},
	}
	err = obj.AddRecipient(rp)
	if err != nil {
		panic(err)
	}

	output, err := key.MarshalCBOR(obj)
	if err != nil {
		panic(err)
	}
	fmt.Printf("COSE(%d bytes): %x...\n", len(output), output[:20])
	// COSE(194 bytes): d8608443a10101a20454adbfc99d99420ac0920c...

	var obj2 cose.EncryptMessage[[]byte]
	err = key.UnmarshalCBOR(output, &obj2)
	if err != nil {
		panic(err)
	}
	err = obj2.Decrypt(encryptor, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypt Payload: %q\n", string(obj2.Payload))
	// Decrypt Payload: "Encryption example for spec - Direct ECDH"

	// Output:
	// Derived key: 56074D506729CA40C4B4FE50C6439893
	// COSE(194 bytes): d8608443a10101a20454adbfc99d99420ac0920c...
	// Decrypt Payload: "Encryption example for spec - Direct ECDH"
}
