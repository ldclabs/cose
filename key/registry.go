// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import (
	"fmt"

	"github.com/ldclabs/cose/iana"
)

// SignerFactory is a function that returns a Signer for the given key.
type SignerFactory func(Key) (Signer, error)

// VerifierFactory is a function that returns a Verifier for the given key.
type VerifierFactory func(Key) (Verifier, error)

// MACerFactory is a function that returns a MACer for the given key.
type MACerFactory func(Key) (MACer, error)

// EncryptorFactory is a function that returns a Encryptor for the given key.
type EncryptorFactory func(Key) (Encryptor, error)

type keyTriple [3]int

var (
	signers    = map[keyTriple]SignerFactory{}
	verifiers  = map[keyTriple]VerifierFactory{}
	macers     = map[keyTriple]MACerFactory{}
	encryptors = map[keyTriple]EncryptorFactory{}
)

// RegisterSigner registers a SignerFactory for the given key type, algorithm, and curve.
// For example, to register a SignerFactory for ed25519 signer:
//
//	key.RegisterSigner(iana.KeyTypeOKP, iana.AlgorithmEdDSA, iana.EllipticCurveEd25519, ed25519.NewSigner)
func RegisterSigner(kty int, alg Alg, crv Crv, fn SignerFactory) {
	signers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

// RegisterVerifier registers a VerifierFactory for the given key type, algorithm, and curve.
func RegisterVerifier(kty int, alg Alg, crv Crv, fn VerifierFactory) {
	verifiers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

// RegisterMACer registers a MACerFactory for the given key type, algorithm.
func RegisterMACer(kty int, alg Alg, fn MACerFactory) {
	macers[keyTriple{int(kty), int(alg), 0}] = fn
}

// RegisterEncryptor registers a EncryptorFactory for the given key type, algorithm.
func RegisterEncryptor(kty int, alg Alg, fn EncryptorFactory) {
	encryptors[keyTriple{int(kty), int(alg), 0}] = fn
}

// Signer returns a Signer for the given key.
// If the key is nil, or SignerFactory for the given key type, algorithm, and curve not registered,
// an error is returned.
func (k Key) Signer() (Signer, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key")
	}

	fn, ok := signers[k.tripleKey()]
	if !ok {
		return nil, fmt.Errorf("signer for %s is not registered", k.tripleName())
	}

	return fn(k)
}

// Verifier returns a Verifier for the given key.
// If the key is nil, or VerifierFactory for the given key type, algorithm, and curve not registered,
// an error is returned.
func (k Key) Verifier() (Verifier, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key")
	}

	fn, ok := verifiers[k.tripleKey()]
	if !ok {
		return nil, fmt.Errorf("verifier for %s is not registered", k.tripleName())
	}

	return fn(k)
}

// MACer returns a MACer for the given key.
// If the key is nil, or MACerFactory for the given key type, algorithm not registered,
// an error is returned.
func (k Key) MACer() (MACer, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key")
	}

	fn, ok := macers[k.tripleKey()]
	if !ok {
		return nil, fmt.Errorf("macer for %s is not registered", k.tripleName())
	}

	return fn(k)
}

// Encryptor returns a Encryptor for the given key.
// If the key is nil, or EncryptorFactory for the given key type, algorithm not registered,
// an error is returned.
func (k Key) Encryptor() (Encryptor, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key")
	}

	fn, ok := encryptors[k.tripleKey()]
	if !ok {
		return nil, fmt.Errorf("encryptor for %s is not registered", k.tripleName())
	}

	return fn(k)
}

func (k Key) tripleKey() keyTriple {
	kty := k.Kty()
	alg := k.Alg()
	crv, _ := k.GetInt(-1) // OKPKeyParameterCrv, EC2KeyParameterCrv
	if alg == iana.AlgorithmReserved {
		switch kty {
		case iana.KeyTypeOKP:
			alg = iana.AlgorithmEdDSA
			crv = iana.EllipticCurveEd25519

		case iana.KeyTypeEC2:
			alg = iana.AlgorithmES256
			crv = iana.EllipticCurveP_256
		}
	}

	return keyTriple{int(kty), int(alg), int(crv)}
}

func (k Key) tripleName() string {
	name := fmt.Sprintf("kty(%d)_alg(%d)", k.Kty(), k.Alg())
	if crv, _ := k.GetInt(-1); crv != 0 {
		name += fmt.Sprintf("_crv(%d)", crv)
	}
	return name
}
