// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCBOREdgeCase(t *testing.T) {
	assert := assert.New(t)

	data, err := MarshalCBOR(func() {})
	assert.Error(err)
	assert.Nil(data)

	assert.Panics(func() {
		MustMarshalCBOR(func() {})
	})
}
