// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"errors"
	"fmt"
	"math"
	"reflect"
)

// IntMap represents a map of int to any value.
// It is the base type of key.Key, cose.Header, cwt.ClaimsMap.
type IntMap map[int]any

// ToInt converts the given value to int, the range is [math.MinInt32, math.MaxInt32].
func ToInt(v any) (int, error) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
		x := rv.Int()
		if x >= math.MinInt32 && x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: ToInt: invalid int %v", v)

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
		x := rv.Uint()
		if x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: ToInt: invalid int %v", v)

	default:
		return 0, fmt.Errorf("cose/key: ToInt: invalid value type %T", v)
	}
}

// Has returns true if the map contains the key.
func (m IntMap) Has(k int) bool {
	_, ok := m[k]
	return ok
}

// GetBool returns the value for the key as an boolean.
// If the key is not present, it returns (false, nil).
// If the underlying value's Kind is not Bool, it returns (false, error).
func (m IntMap) GetBool(k int) (bool, error) {
	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Bool:
			return rv.Bool(), nil

		default:
			return false, fmt.Errorf("cose/key: IntMap.GetBool: invalid value type %T", v)
		}
	}

	return false, nil
}

// GetInt returns the value for the key as an int.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value's range is out of [math.MinInt32, math.MaxInt32], it returns (0, error).
func (m IntMap) GetInt(k int) (int, error) {
	if v, ok := m[k]; ok {
		return ToInt(v)
	}

	return 0, nil
}

// GetInt64 returns the value for the key as an int64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m IntMap) GetInt64(k int) (int64, error) {
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
			return 0, fmt.Errorf("cose/key: IntMap.GetInt64: invalid value %v", v)

		default:
			return 0, fmt.Errorf("cose/key: IntMap.GetInt64: invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetUint64 returns the value for the key as an uint64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m IntMap) GetUint64(k int) (uint64, error) {
	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
			x := rv.Int()
			if x >= 0 {
				return uint64(x), nil
			}
			return 0, fmt.Errorf("cose/key: IntMap.GetUint64: invalid value %v", v)

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
			return rv.Uint(), nil

		default:
			return 0, fmt.Errorf("cose/key: IntMap.GetUint64: invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetBytes returns the value for the key as an []byte.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a slice of bytes or an addressable array of bytes,
// it returns (nil, error).
func (m IntMap) GetBytes(k int) (b []byte, err error) {
	if v, ok := m[k]; ok {
		if b, ok := v.([]byte); ok {
			return b, nil
		}

		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("cose/key: IntMap.GetBytes: invalid value type, %v", r)
			}
		}()
		return reflect.ValueOf(v).Bytes(), nil
	}

	return nil, nil
}

// GetString returns the value for the key as an string.
// If the key is not present, it returns ("", nil).
// If the underlying value is not a string, it returns ("", error).
func (m IntMap) GetString(k int) (string, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.String:
			return reflect.ValueOf(v).String(), nil

		default:
			return "", fmt.Errorf("cose/key: IntMap.GetString: invalid value type %T", v)
		}
	}

	return "", nil
}

// MarshalCBOR implements the CBOR Marshaler interface for IntMap.
func (m IntMap) MarshalCBOR() ([]byte, error) {
	return MarshalCBOR(map[int]any(m))
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for IntMap.
func (m *IntMap) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/key: IntMap.UnmarshalCBOR: nil IntMap")
	}
	return UnmarshalCBOR(data, (*map[int]any)(m))
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m IntMap) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}
