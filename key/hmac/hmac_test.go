// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hmac

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/stretchr/testify/assert"
)

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)
	k, err := GenerateKey(iana.AlgorithmHMAC_256_64)
	assert.NoError(err)
	assert.Equal(iana.AlgorithmHMAC_256_64, int(k.Alg()))
}
