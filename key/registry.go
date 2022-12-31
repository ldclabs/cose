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

type tripleKey [3]int

var (
	signers    = map[tripleKey]SignerFactory{}
	verifiers  = map[tripleKey]VerifierFactory{}
	macers     = map[tripleKey]MACerFactory{}
	encryptors = map[tripleKey]EncryptorFactory{}
)

// RegisterSigner registers a SignerFactory for the given key type, algorithm, and curve.
// For example, to register a SignerFactory for ed25519 signer:
//
//	key.RegisterSigner(iana.KeyTypeOKP, iana.AlgorithmEdDSA, iana.EllipticCurveEd25519, ed25519.NewSigner)
func RegisterSigner(kty, alg, crv int, fn SignerFactory) {
	tk := tripleKey{kty, alg, crv}
	if _, ok := signers[tk]; ok {
		panic(fmt.Errorf("signer for %s is already registered", tk.String()))
	}
	signers[tk] = fn
}

// RegisterVerifier registers a VerifierFactory for the given key type, algorithm, and curve.
func RegisterVerifier(kty, alg, crv int, fn VerifierFactory) {
	tk := tripleKey{kty, alg, crv}
	if _, ok := verifiers[tk]; ok {
		panic(fmt.Errorf("verifier for %s is already registered", tk.String()))
	}
	verifiers[tk] = fn
}

// RegisterMACer registers a MACerFactory for the given key type, algorithm.
func RegisterMACer(kty, alg int, fn MACerFactory) {
	tk := tripleKey{kty, alg, 0}
	if _, ok := macers[tk]; ok {
		panic(fmt.Errorf("macer for %s is already registered", tk.String()))
	}
	macers[tk] = fn
}

// RegisterEncryptor registers a EncryptorFactory for the given key type, algorithm.
func RegisterEncryptor(kty, alg int, fn EncryptorFactory) {
	tk := tripleKey{kty, alg, 0}
	if _, ok := encryptors[tk]; ok {
		panic(fmt.Errorf("encryptor for %s is already registered", tk.String()))
	}
	encryptors[tk] = fn
}

// Signer returns a Signer for the given key.
// If the key is nil, or SignerFactory for the given key type, algorithm, and curve not registered,
// an error is returned.
func (k Key) Signer() (Signer, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key")
	}

	tk := k.tripleKey()
	fn, ok := signers[tk]
	if !ok {
		return nil, fmt.Errorf("signer for %s is not registered", tk.String())
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

	tk := k.tripleKey()
	fn, ok := verifiers[tk]
	if !ok {
		return nil, fmt.Errorf("verifier for %s is not registered", tk.String())
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

	tk := k.tripleKey()
	fn, ok := macers[tk]
	if !ok {
		return nil, fmt.Errorf("macer for %s is not registered", tk.String())
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

	tk := k.tripleKey()
	fn, ok := encryptors[tk]
	if !ok {
		return nil, fmt.Errorf("encryptor for %s is not registered", tk.String())
	}

	return fn(k)
}

func (k Key) tripleKey() tripleKey {
	kty := k.Kty()
	alg := k.Alg()
	crv, _ := k.GetInt(iana.OKPKeyParameterCrv) // or iana.EC2KeyParameterCrv
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

	return tripleKey{kty, int(alg), crv}
}

func (tk tripleKey) String() string {
	str := fmt.Sprintf("kty(%d)_alg(%d)", tk[0], tk[1])
	if tk[2] != 0 {
		str += fmt.Sprintf("_crv(%d)", tk[2])
	}
	return str
}
