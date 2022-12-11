// (c) 2022-2022, LDC Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package key

import "fmt"

type SignerFactory func(Key) (Signer, error)
type VerifierFactory func(Key) (Verifier, error)

type keyTriple [3]int

var (
	signers   = map[keyTriple]SignerFactory{}
	verifiers = map[keyTriple]VerifierFactory{}
)

func RegisterSigner(kty Kty, alg Alg, crv Crv, fn SignerFactory) {
	signers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

func RegisterVerifier(kty Kty, alg Alg, crv Crv, fn VerifierFactory) {
	verifiers[keyTriple{int(kty), int(alg), int(crv)}] = fn
}

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
