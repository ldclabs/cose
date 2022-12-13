// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Op represents the key operation.
type Op string

// Ops represents the key operations.
type Ops []Op

const (
	OpSign   Op = "sign"
	OpVerify Op = "verify"

	OpMacCreate Op = "MAC create"
	OpMacVerify Op = "MAC verify"
)

// Has returns true if the given operation is in the list of operations.
func (os Ops) Has(op Op) bool {
	for _, o := range os {
		if o == op {
			return true
		}
	}
	return false
}

// EmptyOrHas returns true if the list of operations is empty,
// or the given operation is in the list of operations.
func (os Ops) EmptyOrHas(op Op) bool {
	return len(os) == 0 || os.Has(op)
}
