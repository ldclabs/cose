// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey()
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeOKP, k.Kty())
	assert.Equal(iana.AlgorithmEdDSA, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))

	crv, err := k.GetInt(iana.OKPKeyParameterCrv)
	require.NoError(t, err)
	assert.Equal(iana.EllipticCurveEd25519, crv)

	seed, err := k.GetBytes(iana.OKPKeyParameterD)
	require.NoError(t, err)
	assert.Equal(32, len(seed))

	assert.NoError(CheckKey(k))
}

func TestKeyFromSeed(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFromSeed([]byte{1, 2, 3, 4})
	assert.ErrorContains(err, "invalid seed size, expected 32, got 4")
	assert.Nil(k)

	k, err = GenerateKey()
	require.NoError(t, err)
	seed, err := k.GetBytes(iana.OKPKeyParameterD)
	require.NoError(t, err)

	k2, err := KeyFromSeed(seed)
	require.NoError(t, err)
	assert.NoError(CheckKey(k2))
	assert.Equal(k.Kid(), k2.Kid())
	assert.Equal(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))
}

func TestKeyToPrivate(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := KeyToPrivate(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey()
	require.NoError(t, err)
	k2, err := ToPublicKey(k1)
	require.NoError(t, err)

	pk, err = KeyToPrivate(k2)
	assert.ErrorContains(err, `invalid private key`)
	assert.Nil(pk)

	k1[iana.OKPKeyParameterX] = []byte{1, 2, 3, 4}
	pk, err = KeyToPrivate(k1)
	assert.ErrorContains(err, `invalid parameter x`)
	assert.Nil(pk)

	delete(k1, iana.OKPKeyParameterX)
	pk, err = KeyToPrivate(k1)
	assert.NoError(err)

	seed, err := k1.GetBytes(iana.OKPKeyParameterD)
	require.NoError(t, err)
	assert.Equal(seed, pk.Seed())
}

func TestKeyFromPrivate(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey()
	require.NoError(t, err)

	pk, err := KeyToPrivate(k)
	assert.NoError(err)

	k2, err := KeyFromPrivate(pk[1:])
	assert.ErrorContains(err, `invalid key size, expected 64, got 63`)
	assert.Nil(k2)

	k2, err = KeyFromPrivate(pk)
	require.NoError(t, err)
	assert.NoError(CheckKey(k2))
	assert.Equal(k.Kid(), k2.Kid())
	assert.Equal(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))
}

func TestKeyToPublic(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := KeyToPublic(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1, got 0`)
	assert.Nil(pk)

	k1, err := GenerateKey()
	require.NoError(t, err)

	pk, err = KeyToPublic(k1)
	require.NoError(t, err)
	assert.Equal(32, len(pk))

	privK, err := KeyToPrivate(k1)
	require.NoError(t, err)
	assert.True(pk.Equal(privK.Public()))
}

func TestKeyFromPublic(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey()
	require.NoError(t, err)

	pk, err := KeyToPublic(k)
	assert.NoError(err)

	k2, err := KeyFromPublic(pk[1:])
	assert.ErrorContains(err, `invalid key size, expected 32, got 31`)
	assert.Nil(k2)

	k2, err = KeyFromPublic(pk)
	require.NoError(t, err)
	assert.NoError(CheckKey(k2))
	assert.Equal(k.Kid(), k2.Kid())
	assert.NotEqual(key.MustMarshalCBOR(k), key.MustMarshalCBOR(k2))

	pubK, err := ToPublicKey(k)
	require.NoError(t, err)
	assert.Equal(key.MustMarshalCBOR(pubK), key.MustMarshalCBOR(k2))
}

func TestCheckKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	assert.ErrorContains(CheckKey(k), `invalid key type, expected "OKP":1, got 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeOKP,
		iana.KeyParameterAlg: iana.AlgorithmA128GCM,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationSign, iana.KeyOperationMacCreate},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops 9`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterBaseIV: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `redundant parameter 5`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeOKP,
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter crv 0`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: "6",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter crv,`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter d`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterX:   []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter x`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
	}
	assert.ErrorContains(CheckKey(k), `missing parameter x or d`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationVerify},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "sign":1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.OKPKeyParameterX:   key.GetRandomBytes(32),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationVerify},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "sign":1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterX:   key.GetRandomBytes(32),
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationSign},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops, missing "verify":2`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.KeyParameterKid:    "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.KeyParameterKid:    []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.GetRandomBytes(32),
		iana.OKPKeyParameterX:   key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))
}

func TestToPublicKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	pk, err := ToPublicKey(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1, got 0`)
	assert.Nil(pk)

	k, err = GenerateKey()
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

	k[iana.OKPKeyParameterX] = key.GetRandomBytes(32)
	_, err = ToPublicKey(k)
	assert.ErrorContains(err, `parameter x mismatch`)
}

func TestNewSigner(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	signer, err := NewSigner(k)
	assert.ErrorContains(err, `invalid key type, expected "OKP":1, got 0`)
	assert.Nil(signer)

	privK, err := GenerateKey()
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
	assert.ErrorContains(err, `invalid key type, expected "OKP":1, got 0`)
	assert.Nil(verifier)

	privK, err := GenerateKey()
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
