// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/ldclabs/cose/go/key"
)

// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const (
	cborTagCOSESign1 = 18
)

type Sign1Message struct {
	Protected   key.IntMap
	Unprotected key.IntMap
	Payload     cbor.RawMessage
	Signature   []byte

	sm *sign1Message `cbor:"-"`
}

// sign1MessagePrefix represents the fixed prefix of COSE_Sign1_Tagged.
var sign1MessagePrefix = []byte{
	0xd2, // #6.18
	0x84, // array of length 4
}

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected key.IntMap
	Payload     []byte
	Signature   []byte
}

func (sm *Sign1Message) WithSign(k key.Key, external_aad []byte) error {
	signer, err := k.Signer()
	if err != nil {
		return err
	}

	if sm.Protected == nil {
		sm.Protected = key.IntMap{}
	}
	if sm.Unprotected == nil {
		sm.Unprotected = key.IntMap{}
	}

	sm.Protected[HeaderLabelAlgorithm] = k.Alg()

	if kid := k.Kid(); len(kid) > 0 {
		sm.Unprotected[HeaderLabelKeyID] = kid
	}

	sm.sm = &sign1Message{
		Unprotected: sm.Unprotected,
		Payload:     sm.Payload,
	}

	sm.sm.Protected, err = key.MarshalCBOR(sm.Protected)
	if err != nil {
		return err
	}

	if external_aad == nil {
		external_aad = []byte{}
	}

	toBeSigned, err := key.MarshalCBOR([]any{
		"Signature1",    // context
		sm.sm.Protected, // body_protected
		external_aad,    // external_aad
		sm.Payload,      // payload
	})
	if err != nil {
		return err
	}

	sm.sm.Signature, err = signer.Sign(toBeSigned)
	sm.Signature = sm.sm.Signature
	return err
}

func (sm *Sign1Message) MarshalCBOR() ([]byte, error) {
	if sm.sm == nil || sm.sm.Signature == nil {
		return nil, errors.New("cose/cose: Sign1Message.MarshalCBOR: should call Sign1Message.WithSign")
	}

	return key.MarshalCBOR(cbor.Tag{
		Number:  cborTagCOSESign1,
		Content: sm.sm,
	})
}

func (sm *Sign1Message) UnmarshalCBOR(data []byte) error {
	if sm == nil {
		return errors.New("cose/cose: Sign1Message.UnmarshalCBOR: nil Sign1Message")
	}

	if !bytes.HasPrefix(data, sign1MessagePrefix) {
		return errors.New("cose/cose: Sign1Message.UnmarshalCBOR: invalid COSE_Sign1_Tagged object")
	}

	ism := &sign1Message{}
	if err := key.UnmarshalCBOR(data[1:], ism); err != nil {
		return err
	}
	protected := key.IntMap{}
	if err := key.UnmarshalCBOR(ism.Protected, &protected); err != nil {
		return err
	}

	sm.Protected = protected
	sm.Unprotected = ism.Unprotected
	sm.Payload = ism.Payload
	sm.sm = ism
	return nil
}

func (sm *Sign1Message) Verify(k key.Key, external_aad []byte) error {
	if sm.sm == nil || sm.sm.Signature == nil {
		return errors.New("cose/cose: Sign1Message.Verify: should call Sign1Message.UnmarshalCBOR")
	}

	verifier, err := k.Verifier()
	if err != nil {
		return err
	}

	if external_aad == nil {
		external_aad = []byte{}
	}

	toBeSigned, err := key.MarshalCBOR([]any{
		"Signature1",    // context
		sm.sm.Protected, // body_protected
		external_aad,    // external_aad
		sm.Payload,      // payload
	})

	if err != nil {
		return err
	}

	if err = verifier.Verify(toBeSigned, sm.sm.Signature); err != nil {
		return err
	}

	sm.Signature = sm.sm.Signature
	return nil
}

func (sm *Sign1Message) Bytesify() []byte {
	b, _ := sm.MarshalCBOR()
	return b
}
