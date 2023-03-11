// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ecdh

import (
	"bytes"
	goecdh "crypto/ecdh"
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testECDH(a, b key.Key) error {
	ea, err := NewECDHer(a)
	if err != nil {
		return err
	}
	eb, err := NewECDHer(b)
	if err != nil {
		return err
	}

	pubA, err := ToPublicKey(a)
	if err != nil {
		return err
	}

	pubB, err := ToPublicKey(b)
	if err != nil {
		return err
	}

	sa, err := ea.ECDH(pubB)
	if err != nil {
		return err
	}
	sb, err := eb.ECDH(pubA)
	if err != nil {
		return err
	}
	if bytes.Equal(sa, sb) {
		return nil
	}
	return fmt.Errorf("testECDH failed")
}

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeOKP, k.Kty())
	assert.Equal(20, len(k.Kid()))

	crv, err := k.GetInt(iana.EC2KeyParameterCrv)
	require.NoError(t, err)
	assert.Equal(iana.EllipticCurveX25519, crv)

	d, err := k.GetBytes(iana.EC2KeyParameterD)
	require.NoError(t, err)
	assert.True(len(d) > 0)

	assert.NoError(CheckKey(k))

	_, err = GenerateKey(0)
	assert.ErrorContains(err, `invalid crv 0`)

	kb, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	require.NoError(t, testECDH(k, kb))

	for _, crv := range []int{
		iana.EllipticCurveP_256,
		iana.EllipticCurveP_384,
		iana.EllipticCurveP_521,
	} {
		k, err := GenerateKey(crv)
		require.NoError(t, err)
		assert.Equal(iana.KeyTypeEC2, k.Kty())
		assert.Equal(20, len(k.Kid()))

		c, err := k.GetInt(iana.EC2KeyParameterCrv)
		require.NoError(t, err)
		assert.Equal(crv, c)

		assert.NoError(CheckKey(k))
		kb, err := GenerateKey(crv)
		require.NoError(t, err)
		require.NoError(t, testECDH(k, kb))
	}
}

func TestKeyToPrivate(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{iana.EC2KeyParameterD: []byte{}}
	pk, err := KeyToPrivate(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1 or "EC2":2, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey(iana.EllipticCurveP_256)
	require.NoError(t, err)
	k2, err := ToPublicKey(k1)
	require.NoError(t, err)

	pk, err = KeyToPrivate(k2)
	assert.ErrorContains(err, `invalid private key`)
	assert.Nil(pk)

	pk, err = KeyToPrivate(k1)
	assert.NoError(err)
	assert.Equal(goecdh.P256(), pk.Curve())

	k1, err = GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	pk, err = KeyToPrivate(k1)
	assert.NoError(err)
	assert.Equal(goecdh.X25519(), pk.Curve())
}

func TestKeyFromPrivate(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)

	pk, err := KeyToPrivate(k)
	assert.NoError(err)

	k2, err := KeyFromPrivate(pk)
	require.NoError(t, err)
	assert.NoError(CheckKey(k2))
	assert.Equal(k.Kid(), k2.Kid())
	assert.Equal(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))

	for _, crv := range []int{
		iana.EllipticCurveP_256,
		iana.EllipticCurveP_384,
		iana.EllipticCurveP_521,
	} {
		k, err := GenerateKey(crv)
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
	assert.ErrorContains(err, `invalid key type, expected "OKP":1 or "EC2":2, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)

	pk, err = KeyToPublic(k1)
	require.NoError(t, err)

	privK, err := KeyToPrivate(k1)
	require.NoError(t, err)
	assert.True(pk.Equal(privK.Public()))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKid:    k1[iana.KeyParameterKid],
		iana.EC2KeyParameterCrv: k1[iana.EC2KeyParameterCrv],
		iana.EC2KeyParameterX:   pk.Bytes(),
	}

	pk2, err := KeyToPublic(k)
	require.NoError(t, err)
	assert.True(pk.Equal(pk2))

	k1, err = GenerateKey(iana.EllipticCurveP_521)
	require.NoError(t, err)

	pk, err = KeyToPublic(k1)
	require.NoError(t, err)

	privK, err = KeyToPrivate(k1)
	require.NoError(t, err)
	assert.True(pk.Equal(privK.Public()))

	k, err = KeyFromPublic(pk)
	require.NoError(t, err)

	pk2, err = KeyToPublic(k)
	require.NoError(t, err)
	assert.True(pk.Equal(pk2))
}

func TestKeyFromPublic(t *testing.T) {
	assert := assert.New(t)

	for _, crv := range []int{
		iana.EllipticCurveP_256,
		iana.EllipticCurveP_384,
		iana.EllipticCurveP_521,
		iana.EllipticCurveX25519,
	} {
		k, err := GenerateKey(crv)
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
	assert.ErrorContains(CheckKey(k), `invalid key type, expected "OKP":1 or "EC2":2, got 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeEC2,
		iana.KeyParameterAlg: iana.AlgorithmA128GCM,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationDeriveKey, iana.KeyOperationMacCreate},
	}
	assert.ErrorContains(CheckKey(k), `key_ops should be empty for the public key, but got 7`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterD:   []byte{1, 2, 3, 4},
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationDeriveKey, iana.KeyOperationMacCreate},
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
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter y for EC2 key`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.EC2KeyParameterCrv: iana.EllipticCurveX25519,
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
		iana.EC2KeyParameterY:   []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter y`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
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
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.KeyParameterKid:    "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.KeyParameterKid:    []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
		iana.EC2KeyParameterY:   key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
		iana.EC2KeyParameterY:   true,
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterAlg:    iana.AlgorithmECDH_SS_A256KW,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.EC2KeyParameterX:   key.GetRandomBytes(32),
		iana.EC2KeyParameterY:   false,
	}
	assert.NoError(CheckKey(k))
}

func TestToPublicKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := ToPublicKey(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1 or "EC2":2, got 0`)
	assert.Nil(pk)

	k, err = GenerateKey(iana.EllipticCurveP_384)
	require.NoError(t, err)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())
	assert.False(pk.Has(iana.EC2KeyParameterD))
	assert.True(pk.Has(iana.EC2KeyParameterX))
	assert.True(pk.Has(iana.EC2KeyParameterY))

	pk2, err := ToPublicKey(pk)
	require.NoError(t, err)
	assert.Equal(pk, pk2)

	k.SetOps(iana.KeyOperationDeriveKey)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())

	assert.Equal(0, len(pk.Ops()))

	pk2, err = ToPublicKey(pk)
	require.NoError(t, err)
	assert.Equal(pk, pk2)

	k, err = GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())
	assert.False(pk.Has(iana.OKPKeyParameterD))
	assert.True(pk.Has(iana.OKPKeyParameterX))
	assert.False(pk.Has(iana.EC2KeyParameterY))

	pk2, err = ToPublicKey(pk)
	require.NoError(t, err)
	assert.Equal(pk, pk2)

	k.SetOps(iana.KeyOperationDeriveKey)
	pk, err = ToPublicKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(k))
	assert.Equal(k.Kid(), pk.Kid())

	assert.Equal(0, len(pk.Ops()))

	pk2, err = ToPublicKey(pk)
	require.NoError(t, err)
	assert.Equal(pk, pk2)
}

func TestToCompressedKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	ck, err := ToCompressedKey(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1 or "EC2":2, got 0`)
	assert.Nil(ck)

	k, err = GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)

	ck, err = ToCompressedKey(k)
	require.NoError(t, err)
	assert.Equal(k, ck)

	k, err = GenerateKey(iana.EllipticCurveP_256)
	require.NoError(t, err)
	k[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW

	pubK, err := ToPublicKey(k)
	require.NoError(t, err)
	k[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
	k[iana.EC2KeyParameterX] = pubK[iana.EC2KeyParameterX]
	k[iana.EC2KeyParameterY] = pubK[iana.EC2KeyParameterY]
	assert.NoError(CheckKey(k))

	ck, err = ToCompressedKey(k)
	require.NoError(t, err)
	assert.NoError(CheckKey(ck))
	assert.False(ck.Has(iana.KeyParameterKid))
	assert.False(ck.Has(iana.KeyParameterAlg))
	assert.False(ck.Has(iana.EC2KeyParameterX))
	assert.False(ck.Has(iana.EC2KeyParameterY))

	assert.True(pubK.Has(iana.KeyParameterKid))
	assert.True(pubK.Has(iana.KeyParameterAlg))
	assert.True(pubK.Has(iana.EC2KeyParameterX))
	assert.True(pubK.Has(iana.EC2KeyParameterY))
	ck, err = ToCompressedKey(pubK)
	require.NoError(t, err)
	assert.NoError(CheckKey(ck))
	assert.False(ck.Has(iana.KeyParameterKid))
	assert.False(ck.Has(iana.KeyParameterAlg))
	assert.False(ck.Has(iana.EC2KeyParameterD))
	assert.True(ck.Has(iana.EC2KeyParameterX))
	assert.True(ck.Has(iana.EC2KeyParameterY))
	_, err = ck.GetBool(iana.EC2KeyParameterY)
	assert.NoError(err)
}

func TestNewECDHer(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{iana.EC2KeyParameterD: []byte{1, 2, 3}}
	ecdher, err := NewECDHer(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1 or "EC2":2, got 0`)
	assert.Nil(ecdher)

	privK, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	pubK, err := ToPublicKey(privK)
	require.NoError(t, err)

	ecdher, err = NewECDHer(pubK)
	assert.ErrorContains(err, `invalid private key`)
	assert.Nil(ecdher)

	ecdher, err = NewECDHer(privK)
	require.NoError(t, err)
	assert.Equal(privK, ecdher.Key())

	privK2, err := GenerateKey(iana.EllipticCurveX25519)
	require.NoError(t, err)
	pubK2, err := ToPublicKey(privK2)
	require.NoError(t, err)

	secret, err := ecdher.ECDH(privK2)
	assert.ErrorContains(err, `remote should not be private key`)
	assert.Nil(secret)

	privK.SetOps(iana.KeyOperationVerify)
	secret, err = ecdher.ECDH(pubK2)
	assert.ErrorContains(err, "invalid key_ops")
	assert.Nil(secret)

	privK.SetOps()
	secret, err = ecdher.ECDH(pubK2)
	require.NoError(t, err)
	assert.Equal(32, len(secret))

	ecdher2, err := NewECDHer(privK2)
	require.NoError(t, err)
	secret2, err := ecdher2.ECDH(pubK)
	require.NoError(t, err)
	assert.Equal(secret, secret2)
}
