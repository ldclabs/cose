// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesccm

import (
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM1664128, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM1664256, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM6464128, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM6464256, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM16128128, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM16128256, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM64128128, New)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM64128256, New)
}
