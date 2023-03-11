// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/stretchr/testify/assert"
)

func TestTripleKey(t *testing.T) {
	assert := assert.New(t)

	for i, tc := range []struct {
		key       Key
		tripleKey tripleKey
		str       string
	}{
		{
			Key{},
			tripleKey{0, 0, 0},
			"kty(0)_alg(0)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeOKP,
				iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
				iana.OKPKeyParameterCrv: iana.EllipticCurveX25519,
			},
			tripleKey{1, -8, 4},
			"kty(1)_alg(-8)_crv(4)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeOKP,
				iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
				iana.OKPKeyParameterCrv: iana.EllipticCurveX448,
			},
			tripleKey{1, -8, 5},
			"kty(1)_alg(-8)_crv(5)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeOKP,
				iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
				iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
			},
			tripleKey{1, -8, 6},
			"kty(1)_alg(-8)_crv(6)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeOKP,
				iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
				iana.OKPKeyParameterCrv: iana.EllipticCurveEd448,
			},
			tripleKey{1, -8, 7},
			"kty(1)_alg(-8)_crv(7)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeOKP,
				iana.OKPKeyParameterCrv: iana.EllipticCurveEd448,
			},
			tripleKey{1, -8, 7},
			"kty(1)_alg(-8)_crv(7)",
		},
		{
			Key{
				iana.KeyParameterKty: iana.KeyTypeOKP,
			},
			tripleKey{1, -8, 6},
			"kty(1)_alg(-8)_crv(6)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.OKPKeyParameterCrv: iana.EllipticCurveP_256,
			},
			tripleKey{2, -7, 1},
			"kty(2)_alg(-7)_crv(1)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterAlg:    iana.AlgorithmES512,
				iana.OKPKeyParameterCrv: iana.EllipticCurveP_521,
			},
			tripleKey{2, -36, 3},
			"kty(2)_alg(-36)_crv(3)",
		},
		{
			Key{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.OKPKeyParameterCrv: iana.EllipticCurveP_521,
			},
			tripleKey{2, -36, 3},
			"kty(2)_alg(-36)_crv(3)",
		},
		{
			Key{
				iana.KeyParameterKty: iana.KeyTypeEC2,
			},
			tripleKey{2, -7, 1},
			"kty(2)_alg(-7)_crv(1)",
		},
		{
			Key{
				iana.KeyParameterKty: iana.KeyTypeSymmetric,
				iana.KeyParameterAlg: iana.AlgorithmA128GCM,
			},
			tripleKey{4, 1, 0},
			"kty(4)_alg(1)",
		},
	} {
		tk := tc.key.tripleKey()
		assert.Equal(tc.tripleKey, tk, fmt.Sprintf("test case %d", i))
		assert.Equal(tc.str, tk.String(), fmt.Sprintf("test case %d", i))
	}
}

func TestRegister(t *testing.T) {
	t.Run("RegisterSigner", func(t *testing.T) {
		assert := assert.New(t)

		var k Key
		_, err := k.Signer()
		assert.ErrorContains(err, "nil key")

		k = Key{
			iana.KeyParameterKty:    iana.KeyTypeOKP,
			iana.KeyParameterAlg:    -999,
			iana.OKPKeyParameterCrv: -999,
		}
		_, err = k.Signer()
		assert.ErrorContains(err, "kty(1)_alg(-999)_crv(-999) is not registered")

		fn := func(Key) (Signer, error) { return nil, nil }
		RegisterSigner(iana.KeyTypeOKP, -999, -999, fn)
		assert.Panics(func() {
			RegisterSigner(iana.KeyTypeOKP, -999, -999, fn)
		}, "already registered")

		_, err = k.Signer()
		assert.NoError(err)

		delete(signers, k.tripleKey())
		_, err = k.Signer()
		assert.ErrorContains(err, "kty(1)_alg(-999)_crv(-999) is not registered")
	})

	t.Run("RegisterVerifier", func(t *testing.T) {
		assert := assert.New(t)

		var k Key
		_, err := k.Verifier()
		assert.ErrorContains(err, "nil key")

		k = Key{
			iana.KeyParameterKty:    iana.KeyTypeOKP,
			iana.KeyParameterAlg:    -999,
			iana.OKPKeyParameterCrv: -999,
		}
		_, err = k.Verifier()
		assert.ErrorContains(err, "kty(1)_alg(-999)_crv(-999) is not registered")

		fn := func(Key) (Verifier, error) { return nil, nil }
		RegisterVerifier(iana.KeyTypeOKP, -999, -999, fn)
		assert.Panics(func() {
			RegisterVerifier(iana.KeyTypeOKP, -999, -999, fn)
		}, "already registered")

		_, err = k.Verifier()
		assert.NoError(err)

		delete(verifiers, k.tripleKey())
		_, err = k.Verifier()
		assert.ErrorContains(err, "kty(1)_alg(-999)_crv(-999) is not registered")
	})

	t.Run("RegisterMACer", func(t *testing.T) {
		assert := assert.New(t)

		var k Key
		_, err := k.MACer()
		assert.ErrorContains(err, "nil key")

		k = Key{
			iana.KeyParameterKty: iana.KeyTypeSymmetric,
			iana.KeyParameterAlg: -999,
		}
		_, err = k.MACer()
		assert.ErrorContains(err, "kty(4)_alg(-999) is not registered")

		fn := func(Key) (MACer, error) { return nil, nil }
		RegisterMACer(iana.KeyTypeSymmetric, -999, fn)
		assert.Panics(func() {
			RegisterMACer(iana.KeyTypeSymmetric, -999, fn)
		}, "already registered")

		_, err = k.MACer()
		assert.NoError(err)

		delete(macers, k.tripleKey())
		_, err = k.MACer()
		assert.ErrorContains(err, "kty(4)_alg(-999) is not registered")
	})

	t.Run("RegisterEncryptor", func(t *testing.T) {
		assert := assert.New(t)

		var k Key
		_, err := k.Encryptor()
		assert.ErrorContains(err, "nil key")

		k = Key{
			iana.KeyParameterKty: iana.KeyTypeSymmetric,
			iana.KeyParameterAlg: -999,
		}
		_, err = k.Encryptor()
		assert.ErrorContains(err, "kty(4)_alg(-999) is not registered")

		fn := func(Key) (Encryptor, error) { return nil, nil }
		RegisterEncryptor(iana.KeyTypeSymmetric, -999, fn)
		assert.Panics(func() {
			RegisterEncryptor(iana.KeyTypeSymmetric, -999, fn)
		}, "already registered")

		_, err = k.Encryptor()
		assert.NoError(err)

		delete(encryptors, k.tripleKey())
		_, err = k.Encryptor()
		assert.ErrorContains(err, "kty(4)_alg(-999) is not registered")
	})
}
