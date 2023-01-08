// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"fmt"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMAC(t *testing.T) {
	assert := assert.New(t)

	for _, alg := range []int{
		iana.AlgorithmHMAC_256_64,
		iana.AlgorithmHMAC_256_256,
		iana.AlgorithmHMAC_384_384,
		iana.AlgorithmHMAC_512_512,
	} {
		k, err := GenerateKey(alg)
		require.NoError(t, err)
		assert.Equal(alg, int(k.Alg()))
		assert.NoError(CheckKey(k))

		macer, err := New(k)
		require.NoError(t, err)
		assert.Equal(k.Kid(), macer.Key().Kid())

		tag, err := macer.MACCreate([]byte("hello world"))
		require.NoError(t, err)
		_, tagSize := getKeySize(k.Alg())
		assert.Equal(tagSize, len(tag))

		assert.NoError(macer.MACVerify([]byte("hello world"), tag))
		assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")
	}
}

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	k, err := GenerateKey(iana.AlgorithmA128GCM)
	assert.ErrorContains(err, "algorithm mismatch 1")
	assert.Nil(k)

	k, err = GenerateKey(iana.AlgorithmReserved)
	require.NoError(t, err)
	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmHMAC_256_64, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))
}

func TestKeyFrom(t *testing.T) {
	assert := assert.New(t)

	k, err := KeyFrom(iana.AlgorithmReserved, []byte{1, 2, 3})
	assert.ErrorContains(err, "algorithm mismatch 0")
	assert.Nil(k)

	k, err = KeyFrom(iana.AlgorithmHMAC_256_64, []byte{1, 2, 3})
	assert.ErrorContains(err, "invalid key size, expected 32, got 3")
	assert.Nil(k)

	data := key.GetRandomBytes(32)
	k, err = KeyFrom(iana.AlgorithmHMAC_256_64, data)
	require.NoError(t, err)

	assert.Equal(iana.KeyTypeSymmetric, k.Kty())
	assert.Equal(iana.AlgorithmHMAC_256_64, int(k.Alg()))
	assert.Equal(20, len(k.Kid()))
	assert.NoError(CheckKey(k))

	kb, err := k.GetBytes(iana.SymmetricKeyParameterK)
	require.NoError(t, err)
	assert.Equal(data, kb)
	data[0] += 1
	assert.NotEqual(data, kb)
}

func TestCheckKey(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{}
	assert.ErrorContains(CheckKey(k), `invalid key type, expected "Symmetric":4, got 0`)

	k = key.Key{
		iana.KeyParameterKty: iana.KeyTypeSymmetric,
		iana.KeyParameterAlg: iana.AlgorithmA128GCM,
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 1`)

	k = key.Key{
		iana.KeyParameterKty:    iana.KeyTypeSymmetric,
		iana.KeyParameterKeyOps: key.Ops{iana.KeyOperationMacCreate, iana.KeyOperationSign},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter key_ops 1`)

	k = key.Key{
		iana.KeyParameterKty:      iana.KeyTypeSymmetric,
		iana.KeyParameterReserved: true,
	}
	assert.ErrorContains(CheckKey(k), `redundant parameter 0`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.SymmetricKeyParameterK: "hello world",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter k`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `algorithm mismatch 0`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	assert.ErrorContains(CheckKey(k), `invalid key size, expected 32, got 4`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
		iana.KeyParameterKid:        "cose-kid",
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
		iana.KeyParameterKid:        []byte{},
	}
	assert.ErrorContains(CheckKey(k), `invalid parameter kid`)

	k = key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: key.GetRandomBytes(32),
	}
	assert.NoError(CheckKey(k))
}

func TestMACer(t *testing.T) {
	assert := assert.New(t)

	k := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: []byte{1, 2, 3, 4},
	}
	macer, err := New(k)
	assert.ErrorContains(err, `invalid key size, expected 32, got 4`)
	assert.Nil(macer)

	k[iana.SymmetricKeyParameterK] = key.GetRandomBytes(32)
	macer, err = New(k)
	require.NoError(t, err)

	tag, err := macer.MACCreate([]byte("hello world"))
	require.NoError(t, err)

	assert.NoError(macer.MACVerify([]byte("hello world"), tag))
	assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")

	k.SetOps(iana.KeyOperationMacVerify)
	_, err = macer.MACCreate([]byte("hello world"))
	assert.ErrorContains(err, "invalid key_ops")

	k.SetOps(iana.KeyOperationMacCreate)
	assert.ErrorContains(macer.MACVerify([]byte("hello world"), tag), "invalid key_ops")

	k.SetOps(iana.KeyOperationMacVerify, iana.KeyOperationMacCreate)
	tag, err = macer.MACCreate([]byte("hello world 1"))
	require.NoError(t, err)
	assert.NoError(macer.MACVerify([]byte("hello world 1"), tag))

	k[iana.SymmetricKeyParameterK] = key.GetRandomBytes(32)
	assert.ErrorContains(macer.MACVerify([]byte("hello world 1"), tag), "invalid MAC")
}

func TestMACerExamples(t *testing.T) {
	assert := assert.New(t)

	// https://github.com/cose-wg/Examples/tree/master/hmac-examples
	for i, tc := range []struct {
		key  key.Key
		data []byte
		tag  []byte
	}{
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_256,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
			},
			key.HexBytesify("84634D414343A101054054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6"),
		},
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_384_384,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C42718800112233778899AA2122232425262728"),
			},
			key.HexBytesify("84634D414343A101064054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("B3097F70009A11507409598A83E15BBBBF1982DCE28E5AB6D5A6AFF6897BD24BB8B7479622C9401B24090D458206D587"),
		},
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_512_512,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C42718800112233778899AA2122232425262728AABBCCDDEEFFA5A6A7A8A9A0B1B2B3B4"),
			},
			key.HexBytesify("84634D414343A101074054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("CD28A6B3CFBBBF214851B906E050056CB438A8B88905B8B7461977022711A9D8AC5DBC54E29A56D926046B40FC2607C25B344454AA5F68DE09A3E525D3865A05"),
		},
		{
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
				iana.SymmetricKeyParameterK: key.HexBytesify("849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"),
			},
			key.HexBytesify("84634D414343A101044054546869732069732074686520636F6E74656E742E"),
			key.HexBytesify("6F35CAB779F77833"),
		},
	} {
		testmsg := fmt.Sprintf("test case %d", i)
		macer, err := New(tc.key)
		require.NoError(t, err, testmsg)

		tag, err := macer.MACCreate(tc.data)
		require.NoError(t, err, testmsg)
		assert.NoError(macer.MACVerify(tc.data, tag), testmsg)

		assert.Equal(tc.tag, tag, testmsg)
	}
}
