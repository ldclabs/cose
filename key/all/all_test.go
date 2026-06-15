// (c) 2022-present, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package all_test

import (
	"testing"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/all"
)

func TestAllRegistersBuiltInFactories(t *testing.T) {
	ed25519Key := key.Key{
		iana.KeyParameterKty:    iana.KeyTypeOKP,
		iana.KeyParameterAlg:    iana.AlgorithmEdDSA,
		iana.OKPKeyParameterCrv: iana.EllipticCurveEd25519,
		iana.OKPKeyParameterD:   key.HexBytesify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
	}
	if _, err := ed25519Key.Signer(); err != nil {
		t.Fatalf("ed25519 signer not registered: %v", err)
	}

	aesGCMKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmA128GCM,
		iana.SymmetricKeyParameterK: key.HexBytesify("000102030405060708090a0b0c0d0e0f"),
	}
	if _, err := aesGCMKey.Encryptor(); err != nil {
		t.Fatalf("AES-GCM encryptor not registered: %v", err)
	}

	hmacKey := key.Key{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        iana.AlgorithmHMAC_256_64,
		iana.SymmetricKeyParameterK: key.HexBytesify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
	}
	if _, err := hmacKey.MACer(); err != nil {
		t.Fatalf("HMAC MACer not registered: %v", err)
	}
}
