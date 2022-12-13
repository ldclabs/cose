// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
)

// IntKey is a key type for the IntMap.
type IntKey int

// IntMap represents a map of IntKey to any value.
// It is base type of key.Key, cose.Header, cwt.ClaimsMap.
type IntMap map[IntKey]any

// Integer values range https://www.iana.org/assignments/cose/cose.xhtml
const (
	minInt = -65536
	maxInt = 65536
)

// Has returns true if the map contains the key.
func (m IntMap) Has(k IntKey) bool {
	if k < minInt || k > maxInt {
		return false
	}
	_, ok := m[k]
	return ok
}

// GetSmallInt returns the value for the key as an int in [-65536, 65536].
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value's range is out of [-65536, 65536], it returns (0, error).
func (m IntMap) GetSmallInt(k IntKey) (int, error) {
	if k < minInt || k > maxInt {
		return 0, fmt.Errorf("invalid IntKey %d", k)
	}

	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
			x := rv.Int()
			if x >= minInt && x <= maxInt {
				return int(x), nil
			}
			return 0, fmt.Errorf("invalid value %v", v)

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
			x := rv.Uint()
			if x <= uint64(maxInt) {
				return int(x), nil
			}
			return 0, fmt.Errorf("invalid value %v", v)

		default:
			return 0, fmt.Errorf("invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetInt returns the value for the key as an int64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m IntMap) GetInt(k IntKey) (int64, error) {
	if k < minInt || k > maxInt {
		return 0, fmt.Errorf("invalid IntKey %d", k)
	}

	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
			return rv.Int(), nil

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
			x := rv.Uint()
			if x <= math.MaxInt64 {
				return int64(x), nil
			}
			return 0, fmt.Errorf("invalid value %v", v)

		default:
			return 0, fmt.Errorf("invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetUint returns the value for the key as an uint64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m IntMap) GetUint(k IntKey) (uint64, error) {
	if k < minInt || k > maxInt {
		return 0, fmt.Errorf("invalid IntKey %d", k)
	}

	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
			x := rv.Int()
			if x >= 0 {
				return uint64(x), nil
			}
			return 0, fmt.Errorf("invalid value %v", v)

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
			return rv.Uint(), nil

		default:
			return 0, fmt.Errorf("invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetBytes returns the value for the key as an []byte.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a slice of bytes or an addressable array of bytes,
// it returns (nil, error).
func (m IntMap) GetBytes(k IntKey) (b []byte, err error) {
	if k < minInt || k > maxInt {
		return nil, fmt.Errorf("invalid IntKey %d", k)
	}

	if v, ok := m[k]; ok {
		if b, ok := v.([]byte); ok {
			return b, nil
		}

		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("invalid value type, %v", r)
			}
		}()
		return reflect.ValueOf(v).Bytes(), nil
	}

	return nil, nil
}

// GetString returns the value for the key as an string.
// If the key is not present, it returns ("", nil).
// If the underlying value is not a string, it returns ("", error).
func (m IntMap) GetString(k IntKey) (string, error) {
	if k < minInt || k > maxInt {
		return "", fmt.Errorf("invalid IntKey %d", k)
	}

	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.String:
			return reflect.ValueOf(v).String(), nil

		default:
			return "", fmt.Errorf("invalid value type %T", v)
		}
	}

	return "", nil
}

// MarshalCBOR implements the CBOR Marshaler interface for IntMap.
// It sorts the int keys in increasing order and then encode the map.
// The map's capacity should be small, no more than 23 that is enough for COSE, CWT cases.
func (m IntMap) MarshalCBOR() ([]byte, error) {
	var err error
	var b bytes.Buffer
	n := len(m)
	if n > 23 {
		return nil, errors.New("too many map items")
	}

	keys := make([]int, 0, n)
	for k := range m {
		if k < minInt || k > maxInt {
			return nil, fmt.Errorf("invalid IntKey %d", k)
		}

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
