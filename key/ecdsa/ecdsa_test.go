// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ecdsa

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(0)
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeEC2, k.Kty())
	assert.Equal(iana.AlgorithmES256, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))

	crv, err := k.GetInt(iana.EC2KeyParameterCrv)
	require.NoError(t, err)
	assert.Equal(iana.EllipticCurveP_256, crv)

	d, err := k.GetBytes(iana.EC2KeyParameterD)
	require.NoError(t, err)
	assert.True(len(d) > 0)

	assert.NoError(CheckKey(k))

	_, err = GenerateKey(-1)
	assert.ErrorContains(err, `algorithm mismatch -1`)

	for _, alg := range []int{
		iana.AlgorithmES256,
		iana.AlgorithmES384,
		iana.AlgorithmES512,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)
		assert.Equal(alg, int(k.Alg()))
		assert.NoError(CheckKey(k))

		signer, err := NewSigner(k)
		require.NoError(t, err)
		assert.Equal(k.Kid(), signer.Key().Kid())

		sig, err := signer.Sign([]byte("hello world"))
		require.NoError(t, err)

		verifier, err := NewVerifier(k)
		require.NoError(t, err)
		assert.Equal(k.Kid(), verifier.Key().Kid())

		assert.NoError(verifier.Verify([]byte("hello world"), sig))
		assert.ErrorContains(verifier.Verify([]byte("hello world 1"), sig), "invalid signature")
	}
}

func TestKeyToPrivate(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := KeyToPrivate(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey(iana.AlgorithmES256)
	require.NoError(t, err)
	k2, err := ToPublicKey(k1)
	require.NoError(t, err)

	pk, err = KeyToPrivate(k2)
	assert.ErrorContains(err, `invalid private key`)
	assert.Nil(pk)

	pk, err = KeyToPrivate(k1)
	assert.NoError(err)

	k1[iana.EC2KeyParameterX] = []byte{1, 2, 3, 4}
	pk2, err := KeyToPrivate(k1)
	assert.ErrorContains(err, `missing parameter y`)
	assert.Nil(pk2)

	k1[iana.EC2KeyParameterX] = []byte{1, 2, 3, 4}
	k1[iana.EC2KeyParameterY] = []byte{1, 2, 3, 4}
	pk2, err = KeyToPrivate(k1)
	assert.ErrorContains(err, `parameter x mismatch`)
	assert.Nil(pk2)

	k1[iana.EC2KeyParameterX] = pk.PublicKey.X.Bytes()
	k1[iana.EC2KeyParameterY] = []byte{1, 2, 3, 4}
	pk2, err = KeyToPrivate(k1)
	assert.ErrorContains(err, `parameter y mismatch`)
	assert.Nil(pk2)

	k1[iana.EC2KeyParameterY] = pk.PublicKey.Y.Bytes()
	pk2, err = KeyToPrivate(k1)
	assert.NoError(err)
	assert.True(pk.Equal(pk2))
}

func TestKeyFromPrivate(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmES256,
		iana.AlgorithmES384,
		iana.AlgorithmES512,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)

		pk, err := KeyToPrivate(k)
		assert.NoError(err)

		k2, err := KeyFromPrivate(pk)
		require.NoError(t, err)
		assert.NoError(CheckKey(k2))
		assert.Equal(k.Kid(), k2.Kid())
		assert.Equal(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))
	}
}

func TestKeyToPublic(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := KeyToPublic(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey(0)
	require.NoError(t, err)

	pk, err = KeyToPublic(k1)
	require.NoError(t, err)

	privK, err := KeyToPrivate(k1)
	require.NoError(t, err)
	assert.True(pk.Equal(privK.Public()))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    k1[iana.KeyParameterKid],
		iana.KeyParameterAlg:    k1[iana.KeyParameterAlg],
		iana.EC2KeyParameterCrv: k1[iana.EC2KeyParameterCrv],
		iana.EC2KeyParameterX:   pk.X.Bytes(),
		iana.EC2KeyParameterY:   pk.Y.Bytes(),
	}

	pk2, err := KeyToPublic(k)
	require.NoError(t, err)
	assert.True(pk.Equal(pk2))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    k1[iana.KeyParameterKid],
		iana.KeyParameterAlg:    k1[iana.KeyParameterAlg],
		iana.EC2KeyParameterCrv: k1[iana.EC2KeyParameterCrv],
		iana.EC2KeyParameterX:   pk.X.Bytes(),
		iana.EC2KeyParameterY:   pk.Y.Bit(0) == 1,
	}

	pk2, err = KeyToPublic(k)
	require.NoError(t, err)
	assert.True(pk.Equal(pk2))
}

func TestKeyFromPublic(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmES256,
		iana.AlgorithmES384,
		iana.AlgorithmES512,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)

		k1, err := ToPublicKey(k)
		require.NoError(t, err)

		pk, err := KeyToPublic(k)
		assert.NoError(err)

		pk1, err := KeyToPublic(k1)
		assert.NoError(err)
		assert.True(pk.Equal(pk1))

		k2, err := KeyFromPublic(pk)
		require.NoError(t, err)
		assert.NoError(CheckKey(k2))
		assert.Equal(k.Kid(), k2.Kid())
		assert.Equal(k1.Kid(), k2.Kid())
		assert.NotEqual(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))
		assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k2))
	}
}

func TestCheckKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	assert.ErrorContains(CheckKey(k), `invalid key type, expected "EC2":2, got 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeEC2,
		iana.KeyParameterAlg: iana.AlgorithmA128GCM,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationSign, iana.KeyOperationMacCreate},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops 9`)

	k = key.Key{
		iana.KeyParameterKty:      iana.KeyTypeEC2,
		iana.KeyParameterReserved: true,
	}
	assert.ErrorContains(CheckKey(k), `redundant parameter 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeEC2,
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter crv 0`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: "6",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter crv,`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter d`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter x`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
	}
	assert.ErrorContains(CheckKey(k), `missing parameter y`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter y`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   "1",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter y`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
	}
	assert.ErrorContains(CheckKey(k), `missing parameter d or x`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationVerify},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "sign":1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   key.GetRandomBytes(64),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationVerify},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "sign":1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   key.GetRandomBytes(64),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationSign},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "verify":2`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
		iana.KeyParameterKid:    "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
		iana.KeyParameterKid:    []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterAlg:    iana.AlgorithmES256,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   key.GetRandomBytes(64),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterAlg:    iana.AlgorithmES256,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   true,
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterAlg:    iana.AlgorithmES256,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(64),
		iana.EC2KeyParameterX:   key.GetRandomBytes(64),
		iana.EC2KeyParameterY:   false,
	}
	assert.NoError(CheckKey(k))
}

func TestToPublicKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := ToPublicKey(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(pk)

	k, err = GenerateKey(0)
	require.NoError(t, err)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())

	pk2, err := ToPublicKey(pk)
	require.NoError(t, err)
	assert.Equal(pk, pk2)

	k.SetOps(iana.KeyOperationSign)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())

	assert.Equal(1, len(pk.Ops()))
	assert.Equal(iana.KeyOperationVerify, pk.Ops()[0])

	pubK, err := keyToPublic(pk)
	require.NoError(t, err)

	k[iana.EC2KeyParameterX] = key.GetRandomBytes(32)
	k[iana.EC2KeyParameterY] = true
	_, err = ToPublicKey(k)
	assert.ErrorContains(err, `parameter x mismatch`)

	k[iana.EC2KeyParameterX] = pubK.X.Bytes()
	k[iana.EC2KeyParameterY] = key.GetRandomBytes(32)
	_, err = ToPublicKey(k)
	assert.ErrorContains(err, `parameter y mismatch`)

	k[iana.EC2KeyParameterX] = pubK.X.Bytes()
	k[iana.EC2KeyParameterY] = pubK.Y.Bytes()
	pk2, err = ToPublicKey(k)
	assert.NoError(err)
	assert.Equal(key.MustMarshalCBOR(pk), key.MustMarshalCBOR(pk2))

	k[iana.EC2KeyParameterX] = pubK.X.Bytes()
	k[iana.EC2KeyParameterY] = true
	pk2, err = ToPublicKey(k)
	assert.NoError(err)
	assert.Equal(key.MustMarshalCBOR(pk), key.MustMarshalCBOR(pk2))

	k[iana.EC2KeyParameterX] = pubK.X.Bytes()
	k[iana.EC2KeyParameterY] = false
	pk2, err = ToPublicKey(k)
	assert.NoError(err)
	assert.Equal(key.MustMarshalCBOR(pk), key.MustMarshalCBOR(pk2))
}

func TestToCompressedKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	ck, err := ToCompressedKey(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(ck)

	k, err = GenerateKey(0)
	require.NoError(t, err)

	privK, err := KeyToPrivate(k)
	require.NoError(t, err)

	pubK, err := KeyToPublic(k)
	require.NoError(t, err)

	k[iana.EC2KeyParameterX] = privK.PublicKey.X.Bytes()
	k[iana.EC2KeyParameterY] = privK.PublicKey.Y.Bytes()

	ck, err = ToCompressedKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(ck))
	assert.False(ck.Has(iana.KeyParameterKid))
	assert.False(ck.Has(iana.KeyParameterAlg))
	assert.False(ck.Has(iana.EC2KeyParameterX))
	assert.False(ck.Has(iana.EC2KeyParameterY))

	pubK1, err := KeyToPublic(ck)
	require.NoError(t, err)
	assert.Equal(pubK, pubK1)

	pk, err := ToPublicKey(k)
	require.NoError(t, err)
	ck, err = ToCompressedKey(pk)
	require.NoError(t, err)
	assert.NoError(CheckKey(ck))
	assert.False(ck.Has(iana.KeyParameterKid))
	assert.False(ck.Has(iana.KeyParameterAlg))
	assert.False(ck.Has(iana.EC2KeyParameterD))
	assert.True(ck.Has(iana.EC2KeyParameterX))
	assert.True(ck.Has(iana.EC2KeyParameterY))
	_, err = ck.GetBool(iana.EC2KeyParameterY)
	assert.NoError(err)

	pubK2, err := KeyToPublic(ck)
	require.NoError(t, err)
	assert.Equal(pubK, pubK2)
}

func TestNewSigner(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	signer, err := NewSigner(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(signer)

	privK, err := GenerateKey(0)
	require.NoError(t, err)
	pubK, err := ToPublicKey(privK)
	require.NoError(t, err)

	signer, err = NewSigner(pubK)
	assert.ErrorContains(err, `invalid private key`)
	assert.Nil(signer)

	signer, err = NewSigner(privK)
	require.NoError(t, err)
	assert.Equal(privK, signer.Key())

	sig, err := signer.Sign([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(64, len(sig))

	privK.SetOps(iana.KeyOperationVerify)
	sig, err = signer.Sign([]byte("hello"))
	assert.ErrorContains(err, "invalid key_ops")
	assert.Nil(sig)
}

func TestNewVerifier(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	verifier, err := NewVerifier(k)
	assert.ErrorContains(err, `invalid key type, expected "EC2":2, got 0`)
	assert.Nil(verifier)

	privK, err := GenerateKey(0)
	require.NoError(t, err)
	pubK, err := ToPublicKey(privK)
	require.NoError(t, err)

	verifier1, err := NewVerifier(privK)
	require.NoError(t, err)

	verifier2, err := NewVerifier(pubK)
	require.NoError(t, err)
	assert.Equal(key.MustMarshalCBOR(pubK), key.MustMarshalCBOR(verifier1.Key()))
	assert.Equal(key.MustMarshalCBOR(pubK), key.MustMarshalCBOR(verifier2.Key()))
	assert.Equal(pubK, verifier2.Key())

	signer, err := NewSigner(privK)
	require.NoError(t, err)

	sig, err := signer.Sign([]byte("hello"))
	require.NoError(t, err)
	assert.NoError(verifier1.Verify([]byte("hello"), sig))
	assert.NoError(verifier2.Verify([]byte("hello"), sig))

	assert.ErrorContains(verifier2.Verify([]byte("hello1"), sig), "invalid signature")

	pubK.SetOps(iana.KeyOperationSign)
	assert.ErrorContains(verifier2.Verify([]byte("hello"), sig), "invalid key_ops")
}
