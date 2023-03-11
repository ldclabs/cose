// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ldclabs/cose/iana"
)

func TestKeyOps(t *testing.T) {
	assert := assert.New(t)

	var ops Ops
	assert.False(ops.Has(iana.KeyOperationSign))
	assert.True(ops.EmptyOrHas(iana.KeyOperationSign))

	ops = Ops{1, iana.KeyOperationVerify}
	assert.True(ops.Has(iana.KeyOperationSign))
	assert.True(ops.EmptyOrHas(iana.KeyOperationSign))

	assert.True(ops.Has(iana.KeyOperationVerify))
	assert.True(ops.EmptyOrHas(iana.KeyOperationVerify))

	assert.False(ops.Has(iana.KeyOperationEncrypt))
	assert.False(ops.EmptyOrHas(iana.KeyOperationEncrypt))
}
