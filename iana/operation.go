// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package iana

// Key operation values.
//
// See https://datatracker.ietf.org/doc/html/rfc9052#name-key-operation-values
const (
	// Key is used to create signatures. Requires private key fields.
	KeyOperationSign = 1
	// Key is used for verification of signatures.
	KeyOperationVerify = 2
	// Key is used for key transport encryption.
	KeyOperationEncrypt = 3
	// Key is used for key transport decryption. Requires private key fields.
	KeyOperationDecrypt = 4
	// Key is used for key wrap encryption.
	KeyOperationWrapKey = 5
	// Key is used for key wrap decryption.  Requires private key fields.
	KeyOperationUnwrapKey = 6
	// Key is used for deriving keys.  Requires private key fields.
	KeyOperationDeriveKey = 7
	// Key is used for deriving bits not to be used as a key.  Requires private key fields.
	KeyOperationDeriveBits = 8
	// Key is used for creating MACs.
	KeyOperationMacCreate = 9
	// Key is used for validating MACs.
	KeyOperationMacVerify = 10
)
