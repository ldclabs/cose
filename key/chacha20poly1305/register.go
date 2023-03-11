// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chacha20poly1305

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmChaCha20Poly1305, New)
}
