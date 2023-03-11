// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose_test

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"
)

func ExampleSignMessage() {
	// load KeySet
	ks := key.KeySet{}
	err := key.UnmarshalCBOR(key.HexBytesify("82a60102024231312001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e23582057c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3a6010202581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65200321584172992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d947523584200085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d"), &ks)
	if err != nil {
		panic(err)
	}

	// ks is:
	// key.KeySet{
	// 	key.Key{
	// 		iana.KeyParameterKty:    iana.KeyTypeEC2,
	// 		iana.KeyParameterKid:    []byte("11"),
	// 		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
	// 		iana.EC2KeyParameterX:   key.Base64Bytesify("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
	// 		iana.EC2KeyParameterY:   key.Base64Bytesify("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
	// 		iana.EC2KeyParameterD:   key.Base64Bytesify("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	// 	},
	// 	key.Key{
	// 		iana.KeyParameterKty:    iana.KeyTypeEC2,
	// 		iana.KeyParameterKid:    []byte("bilbo.baggins@hobbiton.example"),
	// 		iana.EC2KeyParameterCrv: iana.EllipticCurveP_521,
	// 		iana.EC2KeyParameterX:   key.Base64Bytesify("cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0"),
	// 		iana.EC2KeyParameterY:   key.Base64Bytesify("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
	// 		iana.EC2KeyParameterD:   key.Base64Bytesify("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"),
	// 	},
	// }

	// create a SignMessage object.
	obj := &cose.SignMessage[[]byte]{
		Payload: []byte("This is the content."),
	}

	// get the signers from the KeySet
	signers, err := ks.Signers()
	if err != nil {
		panic(err)
	}

	// sign the message
	err = obj.WithSign(signers, []byte("some external data."))
	if err != nil {
		panic(err)
	}

	coseData, err := cbor.Marshal(obj)
	if err != nil {
		panic(err)
	}

	fmt.Printf("COSE(%d bytes): %x...\n", len(coseData), coseData[:32])
	// COSE(277 bytes): d8628440a054546869732069732074686520636f6e74656e742e828343a10126...

	verifiers, err := ks.Verifiers()
	if err != nil {
		panic(err)
	}
	obj2, err := cose.VerifySignMessage[[]byte](verifiers, coseData, []byte("some external data."))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload: %s\n", string(obj2.Payload))
	// Payload: This is the content.

	// verify with a different external data should fail
	obj3, err := cose.VerifySignMessage[[]byte](verifiers, coseData, []byte("some other external data."))
	if obj3 != nil {
		panic("should be nil")
	}
	fmt.Println(err)
	// cose/key/ecdsa: Verifier.Verify: invalid signature

	// Output:
	// COSE(277 bytes): d8628440a054546869732069732074686520636f6e74656e742e828343a10126...
	// Payload: This is the content.
	// cose/key/ecdsa: Verifier.Verify: invalid signature
}
