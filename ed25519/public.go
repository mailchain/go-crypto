package ed25519

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// PublicKey based on the ed25519 curve
type PublicKey struct {
	Key ed25519.PublicKey
}

// Verify verifies whether sig is a valid signature of message.
func (pk PublicKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(pk.Key, message, sig)
}

// Bytes returns the byte representation of the public key
func (pk PublicKey) Bytes() []byte {
	return pk.Key
}

// PublicKeyFromBytes create a public key from []byte
func PublicKeyFromBytes(keyBytes []byte) (*PublicKey, error) {
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, errors.Errorf("public key must be 32 bytes")
	}

	return &PublicKey{Key: keyBytes}, nil
}
