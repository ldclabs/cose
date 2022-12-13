// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "fmt"

// SignerFactory is a function that returns a Signer for the given key.
type SignerFactory func(Key) (Signer, error)

// VerifierFactory is a function that returns a Verifier for the given key.
type VerifierFactory func(Key) (Verifier, error)

// MACerFactory is a function that returns a MACer for the given key.
type MACerFactory func(Key) (MACer, error)

type keyTriple [3]int

var (
	signers   = map[keyTriple]SignerFactory{}
	verifiers = map[keyTriple]VerifierFactory{}
	macers    = map[keyTriple]MACerFactory{}
)

// RegisterSigner registers a SignerFactory for the given key type, algorithm, and curve.
// For example, to register a SignerFactory for ed25519 signer:
//
//	key.RegisterSigner(key.KtyOKP, key.AlgEdDSA, key.CrvEd25519, ed25519.NewSigner)
func RegisterSigner(kty Kty, alg Alg, crv Crv, fn SignerFactory) {
	signers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

// RegisterVerifier registers a VerifierFactory for the given key type, algorithm, and curve.
func RegisterVerifier(kty Kty, alg Alg, crv Crv, fn VerifierFactory) {
	verifiers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

// RegisterMACer registers a MACerFactory for the given key type, algorithm.
func RegisterMACer(kty Kty, alg Alg, fn MACerFactory) {
	macers[keyTriple{int(kty), int(alg), 0}] = fn
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

func (k Key) tripleKey() keyTriple {
	kty := k.Kty()
	alg := k.Alg()
	crv, _ := k[ParamCrv].(Crv)
	if alg == AlgReserved {
		switch kty {
		case KtyOKP:
			alg = AlgEdDSA
			crv = CrvEd25519

		case KtyEC2:
			alg = AlgES256
			crv = CrvP256
		}
	}

	return keyTriple{int(kty), int(alg), int(crv)}
}

func (k Key) tripleName() string {
	name := k.Kty().String() + "_" + k.Alg().String()
	if crv, ok := k[ParamCrv].(Crv); ok {
		name += "_" + crv.String()
	}
	return name
}
