// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
)

func TestKey(t *testing.T) {
	t.Run("Key.Kty", func(t *testing.T) {
		assert := assert.New(t)

		var k Key
		assert.Equal(iana.KeyTypeReserved, k.Kty())

		k = Key{
			iana.KeyParameterKty: iana.KeyTypeOKP,
		}
		assert.Equal(iana.KeyTypeOKP, k.Kty())
	})

	t.Run("Key.Kid", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{
			iana.KeyParameterKty: iana.KeyTypeOKP,
		}

		assert.Nil(k.Kid())
		k.SetKid([]byte("cose-key"))
		assert.Equal(ByteStr("cose-key"), k.Kid())
	})

	t.Run("Key.Alg", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{
			iana.KeyParameterKty: iana.KeyTypeOKP,
		}

		assert.True(k.Has(iana.KeyParameterKty))
		assert.False(k.Has(iana.KeyParameterAlg))
		assert.Equal(iana.AlgorithmReserved, int(k.Alg()))

		k = Key{
			iana.KeyParameterKty:    iana.KeyTypeEC2,
			iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		}
		assert.True(k.Has(iana.KeyParameterKty))
		assert.False(k.Has(iana.KeyParameterAlg))
		assert.Equal(iana.AlgorithmES256, int(k.Alg()))
	})

	t.Run("Key.Ops", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{
			iana.KeyParameterKty:    iana.KeyTypeEC2,
			iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		}

		assert.Nil(k.Ops())
		assert.False(k.Ops().Has(iana.KeyOperationSign))
		assert.True(k.Ops().EmptyOrHas(iana.KeyOperationSign))

		k.SetOps(iana.KeyOperationSign)
		assert.NotNil(k.Ops())
		assert.True(k.Ops().Has(iana.KeyOperationSign))
		assert.False(k.Ops().Has(iana.KeyOperationVerify))
		assert.False(k.Ops().EmptyOrHas(iana.KeyOperationVerify))

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterKty))
		assert.False(k2.Has(iana.KeyParameterAlg))
		assert.Equal(iana.AlgorithmES256, int(k2.Alg()))
		assert.NotNil(k2.Ops())
		assert.True(k2.Ops().Has(iana.KeyOperationSign))
		assert.False(k2.Ops().Has(iana.KeyOperationVerify))
		assert.False(k2.Ops().EmptyOrHas(iana.KeyOperationVerify))

		k2.SetOps()
		assert.False(k2.Has(iana.KeyParameterKeyOps))
	})

	t.Run("Key.BaseIV", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{
			iana.KeyParameterKty:    iana.KeyTypeEC2,
			iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		}

		assert.Nil(k.BaseIV())
		k[iana.KeyParameterBaseIV] = []byte("base-iv-abc")
		assert.Equal(ByteStr("base-iv-abc"), k.BaseIV())

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.Equal(ByteStr("base-iv-abc"), k.BaseIV())
	})

	t.Run("Key.GetBool", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetBool(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.False(v)

		k = Key{iana.KeyParameterReserved: 0}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetBool(iana.KeyParameterReserved)
		assert.Error(err)
		assert.False(v)

		k = Key{iana.KeyParameterReserved: true}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetBool(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.True(v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetBool(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.True(v)
	})

	t.Run("Key.GetInt", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetInt(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(0, v)

		k = Key{iana.KeyParameterReserved: "1"}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal(0, v)

		k = Key{iana.KeyParameterReserved: 100}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(100, v)

		k = Key{iana.KeyParameterReserved: uint64(1000)}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(1000, v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetInt(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(1000, v)

		k = Key{iana.KeyParameterReserved: math.MaxInt32 + 1}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal(0, v)
	})

	t.Run("Key.GetInt64", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetInt64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(int64(0), v)

		k = Key{iana.KeyParameterReserved: "1"}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt64(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal(int64(0), v)

		k = Key{iana.KeyParameterReserved: 100}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(int64(100), v)

		k = Key{iana.KeyParameterReserved: uint64(1000)}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(int64(1000), v)

		k = Key{iana.KeyParameterReserved: math.MaxInt64}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetInt64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(int64(math.MaxInt64), v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetInt64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(int64(math.MaxInt64), v)
	})

	t.Run("Key.GetUint64", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetUint64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(uint64(0), v)

		k = Key{iana.KeyParameterReserved: "1"}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetUint64(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal(uint64(0), v)

		k = Key{iana.KeyParameterReserved: 100}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetUint64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(uint64(100), v)

		k = Key{iana.KeyParameterReserved: -1000}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetUint64(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal(uint64(0), v)

		k = Key{iana.KeyParameterReserved: math.MaxInt64}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetUint64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(uint64(math.MaxInt64), v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetUint64(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal(uint64(math.MaxInt64), v)
	})

	t.Run("Key.GetBytes", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetBytes(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Nil(v)

		k = Key{iana.KeyParameterReserved: "1"}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetBytes(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Nil(v)

		k = Key{iana.KeyParameterReserved: []byte{1, 2, 3}}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetBytes(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal([]byte{1, 2, 3}, v)

		k = Key{iana.KeyParameterReserved: ByteStr{1, 2, 3}}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetBytes(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal([]byte{1, 2, 3}, v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetBytes(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal([]byte{1, 2, 3}, v)
	})

	t.Run("Key.GetString", func(t *testing.T) {
		assert := assert.New(t)
		k := Key{}

		assert.False(k.Has(iana.KeyParameterReserved))
		v, err := k.GetString(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal("", v)

		k = Key{iana.KeyParameterReserved: 1}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetString(iana.KeyParameterReserved)
		assert.Error(err)
		assert.Equal("", v)

		k = Key{iana.KeyParameterReserved: "hello"}
		assert.True(k.Has(iana.KeyParameterReserved))
		v, err = k.GetString(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal("hello", v)

		var k2 Key
		require.NoError(t, UnmarshalCBOR(MustMarshalCBOR(k), &k2))
		assert.True(k2.Has(iana.KeyParameterReserved))
		v, err = k2.GetString(iana.KeyParameterReserved)
		assert.NoError(err)
		assert.Equal("hello", v)
	})

	var k *Key
	assert.ErrorContains(t, k.UnmarshalCBOR([]byte{0xa0}), "nil IntMap")
}

func TestKeyExamples(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		title string
		key   Key
		res   []byte
	}{
		{
			`128-Bit Symmetric COSE_Key`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        HexBytesify("53796d6d6574726963313238"),
				iana.KeyParameterAlg:        iana.AlgorithmAES_CCM_16_64_128,
				iana.SymmetricKeyParameterK: HexBytesify("231f4c4d4d3051fdc2ec0a3851d5b383"),
			},
			HexBytesify("a40104024c53796d6d6574726963313238030a2050231f4c4d4d3051fdc2ec0a3851d5b383"),
		},
		{
			`256-Bit Symmetric COSE_Key`,
			map[int]any{
				iana.KeyParameterKty:        iana.KeyTypeSymmetric,
				iana.KeyParameterKid:        HexBytesify("53796d6d6574726963323536"),
				iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
				iana.SymmetricKeyParameterK: HexBytesify("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
			},
			HexBytesify("a40104024c53796d6d65747269633235360304205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
		},
		{
			`ECDSA 256-Bit COSE Key`,
			map[int]any{
				iana.KeyParameterKty:    iana.KeyTypeEC2,
				iana.KeyParameterKid:    HexBytesify("4173796d6d65747269634543445341323536"),
				iana.KeyParameterAlg:    iana.AlgorithmES256,
				iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
				iana.EC2KeyParameterX:   HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
				iana.EC2KeyParameterY:   HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
				iana.EC2KeyParameterD:   HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
			},
			HexBytesify("a7010202524173796d6d6574726963454344534132353603262001215820143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f22582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b92358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
		},
	} {
		res, err := MarshalCBOR(tc.key)
		require.NoError(t, err, tc.title)
		assert.Equal(tc.res, res, tc.title)

		var k Key
		require.NoError(t, UnmarshalCBOR(res, &k), tc.title)
		assert.Equal(tc.res, k.Bytesify(), tc.title)
	}
}
