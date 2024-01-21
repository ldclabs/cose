// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"errors"
	"fmt"
	"math"
	"reflect"
)

// CoseMap represents a map of int/text to any value.
// It is the base type of key.Key, cose.Header, cwt.ClaimsMap.
type CoseMap map[any]any

// IntMap is an alias of CoseMap.
type IntMap = CoseMap

// ToInt converts the given value to int, the range is [math.MinInt32, math.MaxInt32].
func ToInt(v any) (int, error) {
	return toInt(reflect.ValueOf(v))
}

// Has returns true if the map contains the key.
func (m CoseMap) Has(k any) bool {
	_, ok := m[k]
	return ok
}

// Get returns the value for the key.
func (m CoseMap) Get(k any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return nil
}

// Set sets the value for the key. The key should be int or string.
func (m CoseMap) Set(k, value any) error {
	k, err := checkKey(k)
	if err != nil {
		return err
	}

	m[k] = value
	return nil
}

// GetBool returns the value for the key as an boolean.
// If the key is not present, it returns (false, nil).
// If the underlying value's Kind is not Bool, it returns (false, error).
func (m CoseMap) GetBool(k any) (bool, error) {
	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Bool:
			return rv.Bool(), nil

		default:
			return false, fmt.Errorf("cose/key: CoseMap.GetBool: invalid value type %T", v)
		}
	}

	return false, nil
}

// GetInt returns the value for the key as an int.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value's range is out of [math.MinInt32, math.MaxInt32], it returns (0, error).
func (m CoseMap) GetInt(k any) (int, error) {
	if v, ok := m[k]; ok {
		return ToInt(v)
	}

	return 0, nil
}

// GetInt64 returns the value for the key as an int64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m CoseMap) GetInt64(k any) (int64, error) {
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
			return 0, fmt.Errorf("cose/key: CoseMap.GetInt64: invalid value %v", v)

		default:
			return 0, fmt.Errorf("cose/key: CoseMap.GetInt64: invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetUint64 returns the value for the key as an uint64.
// If the key is not present, it returns (0, nil).
// If the underlying value's Kind is not Int, Int8, Int16, Int32, Int64, Uint, Uint8, Uint16, Uint32, Int64,
// or the value is overflows, it returns (0, error).
func (m CoseMap) GetUint64(k any) (uint64, error) {
	if v, ok := m[k]; ok {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
			x := rv.Int()
			if x >= 0 {
				return uint64(x), nil
			}
			return 0, fmt.Errorf("cose/key: CoseMap.GetUint64: invalid value %v", v)

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
			return rv.Uint(), nil

		default:
			return 0, fmt.Errorf("cose/key: CoseMap.GetUint64: invalid value type %T", v)
		}
	}

	return 0, nil
}

// GetBytes returns the value for the key as an []byte.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a slice of bytes or an addressable array of bytes,
// it returns (nil, error).
func (m CoseMap) GetBytes(k any) (b []byte, err error) {
	if v, ok := m[k]; ok {
		if b, ok := v.([]byte); ok {
			return b, nil
		}

		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("cose/key: CoseMap.GetBytes: invalid value type, %v", r)
			}
		}()
		return reflect.ValueOf(v).Bytes(), nil
	}

	return nil, nil
}

// GetString returns the value for the key as an string.
// If the key is not present, it returns ("", nil).
// If the underlying value is not a string, it returns ("", error).
func (m CoseMap) GetString(k any) (string, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.String:
			return reflect.ValueOf(v).String(), nil

		default:
			return "", fmt.Errorf("cose/key: CoseMap.GetString: invalid value type %T", v)
		}
	}

	return "", nil
}

// GetMap returns the value for the key as an CoseMap.
// If the key is not present, it returns (nil, nil).
// If the underlying value is not a CoseMap, it returns (nil, error).
func (m CoseMap) GetMap(k any) (CoseMap, error) {
	if v, ok := m[k]; ok {
		if im, ok := v.(CoseMap); ok {
			return im, nil
		}

		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Map:
			iter := rv.MapRange()
			im := make(CoseMap, rv.Len())
			for iter.Next() {
				k, err := toKey(iter.Key())
				if err != nil {
					return nil, err
				}
				im[k] = iter.Value().Interface()
			}
			return im, nil

		default:
			return nil, fmt.Errorf("cose/key: CoseMap.GetMap: invalid value type %T", v)
		}
	}
	return nil, nil
}

// MarshalCBOR implements the CBOR Marshaler interface for CoseMap.
func (m CoseMap) MarshalCBOR() ([]byte, error) {
	return MarshalCBOR(map[any]any(m))
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for CoseMap.
func (m *CoseMap) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/key: CoseMap.UnmarshalCBOR: nil CoseMap")
	}
	var mm map[any]any
	if err := UnmarshalCBOR(data, &mm); err != nil {
		return err
	}

	*m = make(CoseMap, len(mm))
	for k := range mm {
		tk, err := checkKey(k)
		if err != nil {
			return err
		}

		(*m)[tk] = mm[k]
	}
	return nil
}

// MarshalText implements encoding/text interface for CoseMap.
func (m CoseMap) MarshalText() ([]byte, error) {
	data, err := m.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return ByteStr(data).MarshalText()
}

// UnmarshalText implements encoding/text interface for CoseMap.
func (m *CoseMap) UnmarshalText(text []byte) error {
	if m == nil {
		return errors.New("cose/key: CoseMap: UnmarshalText on nil pointer")
	}

	var bstr ByteStr
	if err := bstr.UnmarshalText(text); err != nil {
		return err
	}
	return m.UnmarshalCBOR([]byte(bstr))
}

// MarshalJSON implements encoding/json interface for CoseMap.
func (m CoseMap) MarshalJSON() ([]byte, error) {
	data, err := m.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return ByteStr(data).MarshalJSON()
}

// UnmarshalJSON implements encoding/json interface for CoseMap.
func (m *CoseMap) UnmarshalJSON(text []byte) error {
	if m == nil {
		return errors.New("cose/key: CoseMap: UnmarshalJSON on nil pointer")
	}

	var bstr ByteStr
	if err := bstr.UnmarshalJSON(text); err != nil {
		return err
	}
	return m.UnmarshalCBOR([]byte(bstr))
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m CoseMap) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

func toInt(rv reflect.Value) (int, error) {
	switch rv.Kind() {
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
		x := rv.Int()
		if x >= math.MinInt32 && x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: ToInt: invalid int %v", rv.Interface())

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
		x := rv.Uint()
		if x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: ToInt: invalid int %v", rv.Interface())

	case reflect.Interface:
		return toInt(rv.Elem())

	default:
		return 0, fmt.Errorf("cose/key: ToInt: invalid value type %T", rv.Interface())
	}
}

func toKey(rv reflect.Value) (any, error) {
	switch rv.Kind() {
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int, reflect.Int64:
		x := rv.Int()
		if x >= math.MinInt32 && x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: toKey: invalid int %v", rv.Interface())

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint, reflect.Uint64:
		x := rv.Uint()
		if x <= math.MaxInt32 {
			return int(x), nil
		}
		return 0, fmt.Errorf("cose/key: toKey: invalid int %v", rv.Interface())

	case reflect.String:
		return rv.String(), nil

	case reflect.Interface:
		return toKey(rv.Elem())

	default:
		return 0, fmt.Errorf("cose/key: toKey: invalid value type %T", rv.Interface())
	}
}

func checkKey(k any) (any, error) {
	switch k := k.(type) {
	case int:
		if k >= math.MinInt32 && k <= math.MaxInt32 {
			return k, nil
		}
	case int64:
		if k >= math.MinInt32 && k <= math.MaxInt32 {
			return int(k), nil
		}
	case uint:
		if k <= math.MaxInt32 {
			return int(k), nil
		}
	case uint64:
		if k <= math.MaxInt32 {
			return int(k), nil
		}
	case string:
		return k, nil
	}

	return nil, fmt.Errorf("cose/key: checkKey: invalid key %v", k)
}
