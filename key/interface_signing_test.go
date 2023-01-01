// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdsa"
	"github.com/ldclabs/cose/key/ed25519"
)

func TestSigners(t *testing.T) {
	assert := assert.New(t)

	k1, err := ed25519.GenerateKey()
	require.NoError(t, err)
	s1, err := k1.Signer()
	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(iana.AlgorithmES256)
	require.NoError(t, err)
	s2, err := k2.Signer()
	require.NoError(t, err)

	ss := key.Signers{s1, s2}
	assert.Nil(ss.Lookup([]byte{1, 2, 3}))
	assert.Equal(fmt.Sprintf("%p", s1), fmt.Sprintf("%p", ss.Lookup(k1.Kid())))
	assert.Equal(fmt.Sprintf("%p", s2), fmt.Sprintf("%p", ss.Lookup(k2.Kid())))

	ks := ss.KeySet()
	assert.Equal(2, len(ks))
	assert.Equal(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(ks[0]))
	assert.Equal(key.MustMarshalCBOR(k2), key.MustMarshalCBOR(ks[1]))
}

func TestVerifiers(t *testing.T) {
	assert := assert.New(t)

	k1, err := ed25519.GenerateKey()
	require.NoError(t, err)
	v1, err := k1.Verifier()
	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(iana.AlgorithmES256)
	require.NoError(t, err)
	v2, err := k2.Verifier()
	require.NoError(t, err)

	vs := key.Verifiers{v1, v2}
	assert.Nil(vs.Lookup([]byte{1, 2, 3}))
	assert.Equal(fmt.Sprintf("%p", v1), fmt.Sprintf("%p", vs.Lookup(k1.Kid())))
	assert.Equal(fmt.Sprintf("%p", v2), fmt.Sprintf("%p", vs.Lookup(k2.Kid())))

	ks := vs.KeySet()
	assert.Equal(2, len(ks))
	assert.NotEqual(key.MustMarshalCBOR(k1), key.MustMarshalCBOR(ks[0]))
	pk1, err := ed25519.ToPublicKey(k1)
	require.NoError(t, err)
	assert.Equal(key.MustMarshalCBOR(pk1), key.MustMarshalCBOR(ks[0]))

	assert.NotEqual(key.MustMarshalCBOR(k2), key.MustMarshalCBOR(ks[1]))
	pk2, err := ecdsa.ToPublicKey(k2)
	require.NoError(t, err)
	assert.Equal(key.MustMarshalCBOR(pk2), key.MustMarshalCBOR(ks[1]))
}
