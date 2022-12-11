// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

type Op string
type Ops []Op

const (
	OpSign   Op = "sign"
	OpVerify Op = "verify"

	OpMacCreate Op = "MAC create"
	OpMacVerify Op = "MAC verify"
)

func (os Ops) Has(op Op) bool {
	for _, o := range os {
		if o == op {
			return true
		}
	}
	return false
}

func (os Ops) EmptyOrHas(op Op) bool {
	return len(os) == 0 || os.Has(op)
}
