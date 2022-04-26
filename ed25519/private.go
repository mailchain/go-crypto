package ed25519

import (
	"errors"
	"fmt"
	"io"

	"github.com/mailchain/mailchain/crypto"
	"golang.org/x/crypto/ed25519"
)

// PrivateKey based on the secp256k1 curve
type PrivateKey struct {
	Key ed25519.PrivateKey
}

// Bytes returns the byte representation of the private key
func (pk PrivateKey) Bytes() []byte {
	return pk.Key.Seed()
}

// Sign signs the message with the private key and returns the signature.
func (pk PrivateKey) Sign(message []byte) (signature []byte, err error) {
	if len(pk.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid key length")
	}

	return ed25519.Sign(pk.Key, message), nil
}

// PublicKey return the public key that is derived from the private key
func (pk PrivateKey) PublicKey() crypto.PublicKey {
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey, pk.Key[32:])

	return &PublicKey{Key: publicKey}
}

// PrivateKeyFromBytes get a private key from seed []byte
func PrivateKeyFromBytes(privKey []byte) (*PrivateKey, error) {
	switch len(privKey) {
	case ed25519.SeedSize:
		return &PrivateKey{Key: ed25519.NewKeyFromSeed(privKey)}, nil
	case ed25519.PrivateKeySize:
		return &PrivateKey{Key: privKey}, nil
	default:
		return nil, fmt.Errorf("ed25519: bad key length")
	}
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	_, pPrivKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return PrivateKeyFromBytes(pPrivKey)
}
