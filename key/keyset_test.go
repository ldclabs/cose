// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
	_ "github.com/ldclabs/cose/key/hmac"
)

func TestKeySet(t *testing.T) {
	assert := assert.New(t)

	k1 := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterKid:        key.HexBytesify("53796d6d6574726963323536"),
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: key.HexBytesify("403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"),
	}

	k2 := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeEC2,
		iana.KeyParameterKid:    key.HexBytesify("4173796d6d65747269634543445341323536"),
		iana.KeyParameterAlg:    iana.AlgorithmES256,
		iana.EC2KeyParameterCrv: iana.EllipticCurveP_256,
		iana.EC2KeyParameterX:   key.HexBytesify("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"),
		iana.EC2KeyParameterY:   key.HexBytesify("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"),
		iana.EC2KeyParameterD:   key.HexBytesify("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"),
	}

	ks := key.KeySet{k1, k2}

	k := ks.Lookup([]byte{1, 2, 3})
	assert.Nil(k)

	k = ks.Lookup(k1.Kid())
	assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k))

	k = ks.Lookup(k2.Kid())
	assert.Equal(key.MustMarshalCBOR(k2), key.MustMarshalCBOR(k))

	_, err := ks.Signers()
	assert.ErrorContains(err, "kty(4)_alg(4) is not registered")

	_, err = ks.Verifiers()
	assert.ErrorContains(err, "kty(4)_alg(4) is not registered")

	k1, err = ed25519.GenerateKey()
	require.NoError(t, err)
	ks[0] = k1

	ks2 := key.KeySet{}
	err = key.UnmarshalCBOR(key.MustMarshalCBOR(ks), &ks2)
	require.NoError(t, err, "Marshal and Unmarshal KeySet should work")
	require.Equal(t, 2, len(ks2))

	k = ks2.Lookup(k1.Kid())
	assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(k))

	k = ks2.Lookup(k2.Kid())
	assert.Equal(key.MustMarshalCBOR(k2), key.MustMarshalCBOR(k))

	assert.Equal(key.MustMarshalCBOR(ks), key.MustMarshalCBOR(ks2))

	signers, err := ks.Signers()
	require.NoError(t, err)
	assert.Equal(2, len(signers))
	assert.Equal(k1.Kid(), signers[0].Key().Kid())
	assert.Equal(k2.Kid(), signers[1].Key().Kid())

	verifiers, err := ks.Verifiers()
	require.NoError(t, err)
	assert.Equal(2, len(verifiers))
	assert.Equal(k1.Kid(), verifiers[0].Key().Kid())
	assert.Equal(k2.Kid(), verifiers[1].Key().Kid())
}
