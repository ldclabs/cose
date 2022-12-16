// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chacha20poly1305

import (
	"github.com/ldclabs/cose/go/key"
)

func init() {
	key.RegisterEncryptor(key.KtySymmetric, key.AlgChaCha20Poly1305, New)
}
