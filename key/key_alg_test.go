// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"crypto"
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/stretchr/testify/assert"
)

func TestAlg(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		input  Alg
		output crypto.Hash
	}{
		{iana.AlgorithmES256, crypto.SHA256},
		{iana.AlgorithmHMAC_256_64, crypto.SHA256},
		{iana.AlgorithmHMAC_256_256, crypto.SHA256},
		{iana.AlgorithmES384, crypto.SHA384},
		{iana.AlgorithmHMAC_384_384, crypto.SHA384},
		{iana.AlgorithmES512, crypto.SHA512},
		{iana.AlgorithmHMAC_512_512, crypto.SHA512},
		{0, 0},
		{9, 0},
		{-1, 0},
	} {
		assert.Equal(tc.output, tc.input.HashFunc())
	}
}

func TestComputeHash(t *testing.T) {
	assert := assert.New(t)

	sum, err := ComputeHash(0, []byte("hello"))
	assert.ErrorContains(err, "hash function 0 is not available")
	assert.Nil(sum)

	sum, err = ComputeHash(crypto.SHA256, []byte("hello"))
	assert.NoError(err)
	assert.Equal(32, len(sum))

	sum, err = ComputeHash(crypto.SHA384, []byte("hello"))
	assert.NoError(err)
	assert.Equal(48, len(sum))

	sum, err = ComputeHash(crypto.SHA512, []byte("hello"))
	assert.NoError(err)
	assert.Equal(64, len(sum))
}
