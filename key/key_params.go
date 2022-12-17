// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "strconv"

const (
	// COSE Key Common Parameters
	// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-common-parameters
	// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
	ParamKty    IntKey = 1
	ParamKid    IntKey = 2
	ParamAlg    IntKey = 3
	ParamOps    IntKey = 4
	ParamBaseIV IntKey = 5

	// Reference https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
	// KtyOKP, KtyEC2
	ParamCrv IntKey = -1
	ParamX   IntKey = -2
	ParamY   IntKey = -3
	ParamD   IntKey = -4

	// KtySymmetric
	ParamK IntKey = -1
)

// ParamString returns the name of the key parameter.
func (k Key) ParamString(p IntKey) string {
	switch p {
	case ParamKty:
		return "kty"
	case ParamKid:
		return "kid"
	case ParamAlg:
		return "alg"
	case ParamOps:
		return "key_ops"
	case ParamBaseIV:
		return "Base IV"
	}

	switch k.Kty() {
	case KtyOKP:
		switch p {
		case ParamCrv:
			return "crv"
		case ParamX:
			return "x"
		case ParamD:
			return "d"
		}

	case KtyEC2:
		switch p {
		case ParamCrv:
			return "crv"
		case ParamX:
			return "x"
		case ParamY:
			return "y"
		case ParamD:
			return "d"
		}

	case KtySymmetric:
		if p == ParamK {
			return "k"
		}
	}

	return "UnsupportedKeyTypeParameters(" + k.Kty().String() + ", " + strconv.Itoa(int(p)) + ")"
}
