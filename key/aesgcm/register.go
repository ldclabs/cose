// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aesgcm

import (
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
)

func init() {
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmA128GCM, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmA192GCM, New)
	key.RegisterEncryptor(iana.KeyTypeSymmetric, iana.AlgorithmA256GCM, New)
}
