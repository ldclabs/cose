// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"bytes"
	"errors"
)

// KeySet is a set of Keys.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects.
type KeySet []Key

// MarshalCBOR implements the CBOR Marshaler interface for KeySet.
// A COSE_KeySet MUST have at least one Key (RFC 9052 §7).
func (ks KeySet) MarshalCBOR() ([]byte, error) {
	if len(ks) == 0 {
		return nil, errors.New("cose/key: KeySet.MarshalCBOR: no keys")
	}
	return MarshalCBOR([]Key(ks))
}

// UnmarshalCBOR implements the CBOR Unmarshaler interface for KeySet.
// A COSE_KeySet MUST have at least one Key (RFC 9052 §7).
func (ks *KeySet) UnmarshalCBOR(data []byte) error {
	if ks == nil {
		return errors.New("cose/key: KeySet.UnmarshalCBOR: nil KeySet")
	}

	var keys []Key
	if err := UnmarshalCBOR(data, &keys); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("cose/key: KeySet.UnmarshalCBOR: no keys")
	}

	*ks = keys
	return nil
}

// Lookup returns the first key matching the given key id.
// return nil if there are no keys matching the key id
func (ks KeySet) Lookup(kid []byte) Key {
	for _, k := range ks {
		if bytes.Equal(k.Kid(), kid) {
			return k
		}
	}

	return nil
}

// Signers returns the signers for the keys in the KeySet.
func (ks KeySet) Signers() (Signers, error) {
	signers := make(Signers, 0, len(ks))
	for _, k := range ks {
		signer, err := k.Signer()
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	return signers, nil
}

// Verifiers returns the verifiers for the keys in the KeySet.
func (ks KeySet) Verifiers() (Verifiers, error) {
	verifiers := make(Verifiers, 0, len(ks))
	for _, k := range ks {
		verifier, err := k.Verifier()
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}

	return verifiers, nil
}
