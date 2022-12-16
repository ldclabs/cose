// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesccm

import (
	"github.com/ldclabs/cose/go/key"
)

func init() {
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM1664128, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM1664256, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM6464128, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM6464256, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM16128128, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM16128256, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM64128128, NewAESCCM)
	key.RegisterEncryptor(key.KtySymmetric, key.AlgAESCCM64128256, NewAESCCM)
}
