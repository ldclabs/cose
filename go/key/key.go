// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

const (
	minInt = -65536
	maxInt = 65536
)

type IntKey int
type IntMap map[IntKey]any

// Key
type Key IntMap

func (k Key) Kty() Kty {
	if k == nil {
		return KtyReserved
	}

	v, _ := k.GetInt(ParamKty)
	return Kty(v)
}

func (k Key) Kid() ByteStr {
	if v, ok := k[ParamKid].(ByteStr); ok {
		return v
	}

	v, _ := k.GetBstr(ParamKid)
	return v
}

func (k Key) Alg() Alg {
	v, _ := k.GetInt(ParamAlg)
	return Alg(v)
}

func (k Key) Ops() Ops {
	if v, ok := k[ParamOps]; ok {
		switch x := v.(type) {
		case Ops:
			return x

		case []any:
			ops := make(Ops, len(x))
			for i, v := range x {
				op, ok := v.(string)
				if !ok {
					break
				}

				ops[i] = Op(op)
			}
			return ops
		}
	}

	return nil
}

func (k Key) BaseIV() ByteStr {
	if v, ok := k[ParamBaseIV].(ByteStr); ok {
		return v
	}

	v, _ := k.GetBstr(ParamBaseIV)
	return v
}

func (k Key) GetInt(p IntKey) (int, bool) {
	if v, ok := k[p]; ok {
		switch x := v.(type) {

		case Alg:
			if x >= minInt && x <= maxInt {
				return int(x), true
			}

		case Crv:
			if x >= minInt && x <= maxInt {
				return int(x), true
			}

		case Kty:
			if x >= minInt && x <= maxInt {
				return int(x), true
			}

		case int:
			if x >= minInt && x <= maxInt {
				return x, true
			}

		case int64:
			if x >= minInt && x <= maxInt {
				return int(x), true
			}

		case uint64:
			if x <= uint64(maxInt) {
				return int(x), true
			}
		}
	}

	return 0, false
}

func (k Key) GetBstr(p IntKey) (ByteStr, bool) {
	if v, ok := k[p]; ok {
		switch x := v.(type) {
		case ByteStr:
			return x, true

		case []byte:
			return x, true
		}
	}

	return nil, false
}

func (k Key) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(k))
	for n, v := range k {
		if b, ok := v.(interface{ String() string }); ok {
			m[k.ParamString(n)] = b.String()
		} else if b, ok := v.([]byte); ok {
			m[k.ParamString(n)] = hex.EncodeToString(b)
		} else {
			m[k.ParamString(n)] = v
		}
	}

	return json.Marshal(m)
}

func (k Key) Bytesify() []byte {
	b, _ := IntMap(k).MarshalCBOR()
	return b
}

func (k Key) MarshalCBOR() ([]byte, error) {
	return IntMap(k).MarshalCBOR()
}

func (m IntMap) MarshalCBOR() ([]byte, error) {
	var err error
	var b bytes.Buffer
	n := len(m)
	if n > 23 {
		return nil, errors.New("too many map items")
	}

	keys := make([]int, 0, n)
	for k := range m {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	// CBOR head: map with 0-23 items
	b.WriteByte(0xa0 | byte(n))
	enc := NewEncoder(&b)
	for _, k := range keys {
		if err = enc.Encode(k); err != nil {
			return nil, err
		}
		if err = enc.Encode(m[IntKey(k)]); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}
