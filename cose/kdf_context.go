// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"errors"

	"github.com/ldclabs/cose/key"
)

// KDFContext represents a COSE_KDF_Context object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9053#name-context-information-structu
type KDFContext struct {
	AlgorithmID  int
	PartyUInfo   PartyInfo
	PartyVInfo   PartyInfo
	SuppPubInfo  SuppPubInfo
	SuppPrivInfo []byte
}

type kdfContext0 struct {
	_           struct{} `cbor:",toarray"`
	AlgorithmID int
	PartyUInfo  PartyInfo
	PartyVInfo  PartyInfo
	SuppPubInfo SuppPubInfo
}

type kdfContext1 struct {
	_            struct{} `cbor:",toarray"`
	AlgorithmID  int
	PartyUInfo   PartyInfo
	PartyVInfo   PartyInfo
	SuppPubInfo  SuppPubInfo
	SuppPrivInfo []byte
}

// MarshalCBOR implements the CBOR Marshaler interface for KDFContext.
func (m KDFContext) MarshalCBOR() ([]byte, error) {
	if m.SuppPrivInfo == nil {
		return key.MarshalCBOR(kdfContext0{
			AlgorithmID: m.AlgorithmID,
			PartyUInfo:  m.PartyUInfo,
			PartyVInfo:  m.PartyVInfo,
			SuppPubInfo: m.SuppPubInfo,
		})
	}
	return key.MarshalCBOR(kdfContext1{
		AlgorithmID:  m.AlgorithmID,
		PartyUInfo:   m.PartyUInfo,
		PartyVInfo:   m.PartyVInfo,
		SuppPubInfo:  m.SuppPubInfo,
		SuppPrivInfo: m.SuppPrivInfo,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for KDFContext.
func (m *KDFContext) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: KDFContext.UnmarshalCBOR: nil KDFContext")
	}
	if len(data) == 0 {
		return errors.New("cose/cose: KDFContext.UnmarshalCBOR: empty data")
	}

	switch data[0] {
	case 0x84:
		var v kdfContext0
		if err := key.UnmarshalCBOR(data, &v); err != nil {
			return err
		}
		m.AlgorithmID = v.AlgorithmID
		m.PartyUInfo = v.PartyUInfo
		m.PartyVInfo = v.PartyVInfo
		m.SuppPubInfo = v.SuppPubInfo

	case 0x85:
		var v kdfContext1
		if err := key.UnmarshalCBOR(data, &v); err != nil {
			return err
		}
		m.AlgorithmID = v.AlgorithmID
		m.PartyUInfo = v.PartyUInfo
		m.PartyVInfo = v.PartyVInfo
		m.SuppPubInfo = v.SuppPubInfo
		m.SuppPrivInfo = v.SuppPrivInfo

	default:
		return errors.New("cose/cose: KDFContext.UnmarshalCBOR: invalid data")
	}

	return nil
}

// SuppPubInfo represents a SuppPubInfo object.
type SuppPubInfo struct {
	KeyDataLength uint // bits of the desired output value
	Protected     Headers
	Other         []byte
}

type suppPubInfo0 struct {
	_             struct{} `cbor:",toarray"`
	KeyDataLength uint
	Protected     []byte
}

type suppPubInfo1 struct {
	_             struct{} `cbor:",toarray"`
	KeyDataLength uint
	Protected     []byte
	Other         []byte
}

// MarshalCBOR implements the CBOR Marshaler interface for SuppPubInfo.
func (m SuppPubInfo) MarshalCBOR() ([]byte, error) {
	protected := []byte{}
	if len(m.Protected) > 0 {
		var err error
		protected, err = key.MarshalCBOR(m.Protected)
		if err != nil {
			return nil, err
		}
	}

	if m.Other == nil {
		return key.MarshalCBOR(suppPubInfo0{
			KeyDataLength: m.KeyDataLength,
			Protected:     protected,
		})
	}

	return key.MarshalCBOR(suppPubInfo1{
		KeyDataLength: m.KeyDataLength,
		Protected:     protected,
		Other:         m.Other,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for SuppPubInfo.
func (m *SuppPubInfo) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/cose: SuppPubInfo.UnmarshalCBOR: nil SuppPubInfo")
	}
	if len(data) == 0 {
		return errors.New("cose/cose: SuppPubInfo.UnmarshalCBOR: empty data")
	}

	switch data[0] {
	case 0x82:
		var v suppPubInfo0
		if err := key.UnmarshalCBOR(data, &v); err != nil {
			return err
		}
		m.KeyDataLength = v.KeyDataLength
		if len(v.Protected) > 0 {
			if err := key.UnmarshalCBOR(v.Protected, &m.Protected); err != nil {
				return err
			}
		}

	case 0x83:
		var v suppPubInfo1
		if err := key.UnmarshalCBOR(data, &v); err != nil {
			return err
		}
		m.KeyDataLength = v.KeyDataLength
		m.Other = v.Other
		if len(v.Protected) > 0 {
			if err := key.UnmarshalCBOR(v.Protected, &m.Protected); err != nil {
				return err
			}
		}

	default:
		return errors.New("cose/cose: SuppPubInfo.UnmarshalCBOR: invalid data")
	}

	return nil
}

// PartyInfo represents a PartyInfo object.
type PartyInfo struct {
	_        struct{} `cbor:",toarray"`
	Identity []byte
	Nonce    []byte
	Other    []byte
}
