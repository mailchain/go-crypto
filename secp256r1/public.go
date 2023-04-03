package secp256r1

import (
	"fmt"
	"math/big"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/mailchain/go-crypto"
)

// PublicKey based on the p256 curve
type PublicKey struct {
	Key ecdsa.PublicKey
}

// Verify verifies whether sig is a valid signature of message.
func (pk PublicKey) Verify(message, sig []byte) bool {
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(&pk.Key, message, r, s)
}

// Bytes returns the byte representation of the public key
func (pk PublicKey) Bytes() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), pk.Key.X, pk.Key.Y)
}

// PublicKeyFromBytes create a public key from []byte
func PublicKeyFromBytes(keyBytes []byte) (crypto.PublicKey, error) {
	if len(keyBytes) != 33 {
		return nil, fmt.Errorf("public key must be 33 bytes")
	}
	key := ecdsa.PublicKey{Curve: elliptic.P256()}
	key.X, key.Y = elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)

	return &PublicKey{Key: key}, nil
}
