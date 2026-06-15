// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"
)

func TestRFC9052AppendixCSignatureWithCriticality(t *testing.T) {
	data := rfc9052Hex("d8628456a2687265736572766564f40281687265736572766564a054546869732069732074686520636f6e74656e742e818343a10126a10442313158403fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c")

	verifiers, err := key.KeySet{rfc9052Key11()}.Verifiers()
	require.NoError(t, err)

	msg, err := VerifySignMessage[[]byte](verifiers, data, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("This is the content."), msg.Payload)
	assert.Equal(t, false, msg.Protected.Get("reserved"))
	assert.Equal(t, []any{"reserved"}, msg.Protected.Get(iana.HeaderParameterCrit))
	assert.Equal(t, data, msg.Bytesify())
}

func TestRFC9052AppendixCTaggedSignedExamples(t *testing.T) {
	verifier, err := rfc9052Key11().Verifier()
	require.NoError(t, err)
	verifiers := key.Verifiers{verifier}

	t.Run("C.1.1 Single Signature", func(t *testing.T) {
		data := rfc9052Hex("d8628440a054546869732069732074686520636f6e74656e742e818343a10126a1044231315840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a")

		msg, err := VerifySignMessage[[]byte](verifiers, data, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("This is the content."), msg.Payload)
		assert.Equal(t, data, msg.Bytesify())
	})

	t.Run("C.2.1 Single ECDSA Signature", func(t *testing.T) {
		data := rfc9052Hex("d28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36")

		msg, err := VerifySign1Message[[]byte](verifier, data, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("This is the content."), msg.Payload)
		assert.Equal(t, data, msg.Bytesify())
	})
}

func TestRFC9052AppendixCKeySets(t *testing.T) {
	t.Run("C.7.1 Public Keys", func(t *testing.T) {
		ks := key.KeySet{
			rfc9052MeriadocPublicKey(),
			rfc9052Key11Public(),
			rfc9052BilboPublicKey(),
			rfc9052PeregrinPublicKey(),
		}
		data := key.MustMarshalCBOR(ks)
		assert.Len(t, data, 481)

		var decoded key.KeySet
		require.NoError(t, key.UnmarshalCBOR(data, &decoded))
		assert.Equal(t, key.MustMarshalCBOR(ks), key.MustMarshalCBOR(decoded))
		assert.Equal(t, []byte("meriadoc.brandybuck@buckland.example"), []byte(decoded.Lookup([]byte("meriadoc.brandybuck@buckland.example")).Kid()))
		assert.Equal(t, []byte("11"), []byte(decoded.Lookup([]byte("11")).Kid()))
		assert.Equal(t, []byte("bilbo.baggins@hobbiton.example"), []byte(decoded.Lookup([]byte("bilbo.baggins@hobbiton.example")).Kid()))
		assert.Equal(t, []byte("peregrin.took@tuckborough.example"), []byte(decoded.Lookup([]byte("peregrin.took@tuckborough.example")).Kid()))
	})

	t.Run("C.7.2 Private Keys", func(t *testing.T) {
		ks := key.KeySet{
			rfc9052MeriadocPrivateKey(),
			rfc9052Key11(),
			rfc9052BilboPrivateKey(),
			rfc9052OurSecret(),
			rfc9052PeregrinPrivateKey(),
			rfc9052OurSecret2(),
			rfc9052KeyWrapSecret(),
		}
		data := key.MustMarshalCBOR(ks)
		assert.Len(t, data, 816)

		var decoded key.KeySet
		require.NoError(t, key.UnmarshalCBOR(data, &decoded))
		assert.Equal(t, key.MustMarshalCBOR(ks), key.MustMarshalCBOR(decoded))
		assert.Equal(t, []byte("our-secret"), []byte(decoded.Lookup([]byte("our-secret")).Kid()))
		assert.Equal(t, []byte("our-secret2"), []byte(decoded.Lookup([]byte("our-secret2")).Kid()))
		assert.Equal(t, []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"), []byte(decoded.Lookup([]byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037")).Kid()))
	})
}

func rfc9052MeriadocPublicKey() key.Key {
	return key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("meriadoc.brandybuck@buckland.example"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   rfc9052Hex("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
		iana.EC2KeyParameterY:   rfc9052Hex("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
	}
}

func rfc9052MeriadocPrivateKey() key.Key {
	k := rfc9052MeriadocPublicKey()
	k[iana.EC2KeyParameterD] = rfc9052Hex("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
	return k
}

func rfc9052Key11Public() key.Key {
	return key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("11"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   rfc9052Hex("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
		iana.EC2KeyParameterY:   rfc9052Hex("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
	}
}

func rfc9052Key11() key.Key {
	k := rfc9052Key11Public()
	k[iana.EC2KeyParameterD] = rfc9052Hex("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3")
	return k
}

func rfc9052BilboPublicKey() key.Key {
	return key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("bilbo.baggins@hobbiton.example"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_521,
		iana.EC2KeyParameterX:   rfc9052Hex("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad"),
		iana.EC2KeyParameterY:   rfc9052Hex("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475"),
	}
}

func rfc9052BilboPrivateKey() key.Key {
	k := rfc9052BilboPublicKey()
	k[iana.EC2KeyParameterD] = rfc9052Hex("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")
	return k
}

func rfc9052PeregrinPublicKey() key.Key {
	return key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    []byte("peregrin.took@tuckborough.example"),
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   rfc9052Hex("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
		iana.EC2KeyParameterY:   rfc9052Hex("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb"),
	}
}

func rfc9052PeregrinPrivateKey() key.Key {
	k := rfc9052PeregrinPublicKey()
	k[iana.EC2KeyParameterD] = rfc9052Hex("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
	return k
}

func rfc9052OurSecret() key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("our-secret"),
		iana.SymmetricKeyParameterK: rfc9052Hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
	}
}

func rfc9052OurSecret2() key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("our-secret2"),
		iana.SymmetricKeyParameterK: rfc9052Hex("849b5786457c1491be3a76dcea6c4271"),
	}
}

func rfc9052KeyWrapSecret() key.Key {
	return key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        []byte("018c0ae5-4d9b-471b-bfd6-eef314bc7037"),
		iana.SymmetricKeyParameterK: rfc9052Hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
	}
}

func rfc9052Hex(s string) []byte {
	return key.HexBytesify(s)
}
