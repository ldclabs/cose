// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
)

// Mac0Message represents a COSE_Mac0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer
type Mac0Message[T any] struct {
	Protected   Headers
	Unprotected Headers
	Payload     T

	mm    *mac0Message
	toMac []byte
}

// VerifyMac0Message verifies and decodes a COSE_Mac0 message with a MACer and returns a *Mac0Message.
// `externalData` should be the same as the one used in `Mac0Message.ComputeAndEncode`.
func VerifyMac0Message[T any](macer key.MACer, coseData, externalData []byte) (*Mac0Message[T], error) {
	m := &Mac0Message[T]{}
	if err := m.UnmarshalCBOR(coseData); err != nil {
		return nil, err
	}
	if err := m.Verify(macer, externalData); err != nil {
		return nil, err
	}
	return m, nil
}

// ComputeAndEncode computes and encodes a COSE_Mac0 message with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Mac0Message[T]) ComputeAndEncode(macer key.MACer, externalData []byte) ([]byte, error) {
	if err := m.Compute(macer, externalData); err != nil {
		return nil, err
	}
	return m.MarshalCBOR()
}

// mac0Message represents a COSE_Mac0 structure to encode and decode.
type mac0Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected Headers
	Payload     []byte // can be nil
	Tag         []byte
}

// Compute computes a COSE_Mac0 message' MAC with a MACer.
// `externalData` can be nil. https://datatracker.ietf.org/doc/html/rfc9052#name-externally-supplied-data
func (m *Mac0Message[T]) Compute(macer key.MACer, externalData []byte) error {
	if m.Protected == nil {
		m.Protected = Headers{}

		if alg := macer.Key().Alg(); alg != key.AlgReserved {
			m.Protected[HeaderLabelAlgorithm] = alg
		}
	}

	if m.Unprotected == nil {
		m.Unprotected = Headers{}

		if kid := macer.Key().Kid(); len(kid) > 0 {
			m.Unprotected[HeaderLabelKeyID] = kid
		}
	}

	mm := &mac0Message{
		Protected:   []byte{},
		Unprotected: m.Unprotected,
	}

	var err error
	if len(m.Protected) > 0 {
		mm.Protected, err = key.MarshalCBOR(m.Protected)
		if err != nil {
			return err
		}
	}

	switch v := any(m.Payload).(type) {
	case []byte:
		mm.Payload = v
	case cbor.RawMessage:
		mm.Payload = v
	default:
		mm.Payload, err = key.MarshalCBOR(m.Payload)
		if err != nil {
			return err
		}
	}

	m.toMac, err = mm.toMac(externalData)
	if err != nil {
		return err
	}

	if mm.Tag, err = macer.MACCreate(m.toMac); err == nil {
		m.mm = mm
	}
	return err
}

// Verify verifies a COSE_Mac0 message' MAC with a MACer.
// It should call `Mac0Message.UnmarshalCBOR` before calling this method.
// `externalData` should be the same as the one used in Mac0Message.Compute.
func (m *Mac0Message[T]) Verify(macer key.MACer, externalData []byte) error {
	if m.mm == nil || m.mm.Tag == nil {
		return errors.New("cose/go/cose: Mac0Message.Verify: should call Mac0Message.UnmarshalCBOR")
	}

	var err error
	m.toMac, err = m.mm.toMac(externalData)
	if err != nil {
		return err
	}

	return macer.MACVerify(m.toMac, m.mm.Tag)
}

func (mm *mac0Message) toMac(external_aad []byte) ([]byte, error) {
	if external_aad == nil {
		external_aad = []byte{}
	}
	// MAC_structure https://datatracker.ietf.org/doc/html/rfc9052#name-how-to-compute-and-verify-a
	return key.MarshalCBOR([]any{
		"MAC0",       // context
		mm.Protected, // body_protected
		external_aad, // external_aad
		mm.Payload,   // payload
	})
}

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const cborTagCOSEMac0 = 17

// MarshalCBOR implements the CBOR Marshaler interface for Mac0Message.
// It should call `Mac0Message.WithSign` before calling this method.
func (m *Mac0Message[T]) MarshalCBOR() ([]byte, error) {
	if m.mm == nil || m.mm.Tag == nil {
		return nil, errors.New("cose/go/cose: Mac0Message.MarshalCBOR: should call Mac0Message.Compute")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSEMac0,
		Content: m.mm,
	})
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for Mac0Message.
func (m *Mac0Message[T]) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cose/go/cose: Mac0Message.UnmarshalCBOR: nil Mac0Message")
	}

	if bytes.HasPrefix(data, cwtPrefix) {
		data = data[2:]
	}

	// support untagged message
	if bytes.HasPrefix(data, mac0MessagePrefix) {
		data = data[1:]
	}

	mm := &mac0Message{}
	if err := key.UnmarshalCBOR(data, mm); err != nil {
		return err
	}

	protected := Headers{}
	if len(mm.Protected) > 0 {
		if err := key.UnmarshalCBOR(mm.Protected, &protected); err != nil {
			return err
		}
	}

	if len(mm.Payload) > 0 {
		switch any(m.Payload).(type) {
		case []byte:
			m.Payload = any(mm.Payload).(T)
		case cbor.RawMessage:
			m.Payload = any(mm.Payload).(T)
		default:
			if err := key.UnmarshalCBOR(mm.Payload, &m.Payload); err != nil {
				return err
			}
		}
	}

	m.Protected = protected
	m.Unprotected = mm.Unprotected
	m.mm = mm
	return nil
}

// Bytesify returns a CBOR-encoded byte slice.
// It returns nil if MarshalCBOR failed.
func (m *Mac0Message[T]) Bytesify() []byte {
	b, _ := m.MarshalCBOR()
	return b
}

// Tag returns the MAC tag of the Mac0Message.
// If the MAC is not computed, it returns nil.
func (m *Mac0Message[T]) Tag() []byte {
	if m.mm == nil {
		return nil
	}
	return m.mm.Tag
}
