// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "bytes"

// KeySet is a set of Keys.
type KeySet []Key

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
