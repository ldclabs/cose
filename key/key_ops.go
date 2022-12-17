// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Ops represents the key operations.
type Ops []IntKey

// Key Operation Values
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-common-parameters
const (
	OpSign       IntKey = 1  // "sign"
	OpVerify     IntKey = 2  // "verify"
	OpEncrypt    IntKey = 3  // "encrypt"
	OpDecrypt    IntKey = 4  // "decrypt"
	OpWrapKey    IntKey = 5  // "wrap key"
	OpUnwrapKey  IntKey = 6  // "unwrap key"
	OpDeriveKey  IntKey = 7  // "derive key"
	OpDeriveBits IntKey = 8  // "derive bits"
	OpMACCreate  IntKey = 9  // "MAC create"
	OpMACVerify  IntKey = 10 // "MAC verify"
)

// Has returns true if the given operation is in the list of operations.
func (os Ops) Has(op IntKey) bool {
	for _, o := range os {
		if o == op {
			return true
		}
	}
	return false
}

// EmptyOrHas returns true if the list of operations is empty,
// or the given operation is in the list of operations.
func (os Ops) EmptyOrHas(op IntKey) bool {
	return len(os) == 0 || os.Has(op)
}
