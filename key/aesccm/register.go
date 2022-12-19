// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesccm

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_16_64_128, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_16_64_256, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_64_64_128, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_64_64_256, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_16_128_128, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_16_128_256, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_64_128_128, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmAES_CCM_64_128_256, New)
}
