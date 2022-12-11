// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import "github.com/ldclabs/cose/go/key"

// COSE Header labels registered in the IANA "COSE Header Parameters" registry.
// https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const (
	HeaderLabelReserved          key.IntKey = 0
	HeaderLabelAlgorithm         key.IntKey = 1
	HeaderLabelCritical          key.IntKey = 2
	HeaderLabelContentType       key.IntKey = 3
	HeaderLabelKeyID             key.IntKey = 4
	HeaderLabelIV                key.IntKey = 5
	HeaderLabelPartialIV         key.IntKey = 6
	HeaderLabelCounterSignature  key.IntKey = 7
	HeaderLabelCounterSignature0 key.IntKey = 9
)
