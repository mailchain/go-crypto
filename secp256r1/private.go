package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mailchain/go-crypto"
)

// PrivateKey based on the p256 curve
type PrivateKey struct {
	key  ecdsa.PrivateKey
	rand io.Reader
}

// Bytes returns the byte representation of the private key
func (pk PrivateKey) Bytes() []byte {
	return ethcrypto.FromECDSA(&pk.key)
}

// Sign signs the message with the private key and returns the signature.
func (pk PrivateKey) Sign(message []byte) (signature []byte, err error) {
	r, s, err := ecdsa.Sign(pk.rand, &pk.key, message)
	if err != nil {
		return nil, err
	}

	// normalize
	r, s = ecNormalizeSignature(r, s, pk.key.Curve)
	// serialize
	buf := make([]byte, 64)
	r.FillBytes(buf[:32])
	s.FillBytes(buf[32:])
	return buf, nil
}

// PublicKey return the public key that is derived from the private key
func (pk PrivateKey) PublicKey() crypto.PublicKey {
	return &PublicKey{Key: pk.key.PublicKey}
}

// PrivateKeyFromBytes get a private key from seed []byte
func PrivateKeyFromBytes(privKey []byte) (*PrivateKey, error) {
	ecdsaPrivateKey, err := toECDSA(privKey)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: *ecdsaPrivateKey, rand: rand.Reader}, nil
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: *key, rand: rand}, nil
}

// ecNormalizeSignature ensures strict compliance with the EC spec by returning
// S mod n for the appropriate keys curve.
//
// Details:
//
//	Step #6 of the ECDSA algorithm [x] defines an `S` value mod n[0],
//	but most signers (OpenSSL, SoftHSM, YubiHSM) don't return a strict modulo.
//	This variability was exploited with transaction malleability in Bitcoin,
//	leading to BIP#62.  BIP#62 Rule #5[1] requires that signatures return a
//	strict S = ... mod n which this function forces implemented in btcd here [2]
//	[0]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
//	[1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#new-rules
//	[2]: https://github.com/btcsuite/btcd/blob/master/btcec/signature.go#L49
//
// See also Ecadlabs Signatory:
// https://github.com/ecadlabs/signatory/blob/f57871c2300cb5a53236ea5fcb4f203012b4fe41/pkg/cryptoutils/crypto.go#L17
func ecNormalizeSignature(r, s *big.Int, c elliptic.Curve) (*big.Int, *big.Int) {
	r = new(big.Int).Set(r)
	s = new(big.Int).Set(s)

	order := c.Params().N
	quo := new(big.Int).Quo(order, new(big.Int).SetInt64(2))
	if s.Cmp(quo) > 0 {
		s = s.Sub(order, s)
	}
	return r, s
}

func toECDSA(pkBytes []byte) (*ecdsa.PrivateKey, error) {
	k := new(big.Int).SetBytes(pkBytes)
	curveOrder := elliptic.P256().Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid private key for curve Nist P256")
	}

	priv := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: k,
	}

	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/ecdsa/ecdsa.go;l=149
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(k.Bytes())
	return &priv, nil
}
