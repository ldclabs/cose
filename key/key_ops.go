// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

// Ops represents the key operations.
type Ops []int

// Has returns true if the given operation is in the list of operations.
func (os Ops) Has(op int) bool {
	for _, o := range os {
		if o == op {
			return true
		}
	}
	return false
}

// EmptyOrHas returns true if the list of operations is empty,
// or the given operation is in the list of operations.
func (os Ops) EmptyOrHas(op int) bool {
	return len(os) == 0 || os.Has(op)
}
