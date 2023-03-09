package secp256k1

import (
	"crypto/ecdsa"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/mailchain/go-crypto"
)

// PublicKey based on the secp256k1 curve
type PublicKey struct {
	ecdsa ecdsa.PublicKey
}

// Verify verifies whether sig is a valid signature of message.
func (pk PublicKey) Verify(message, sig []byte) bool {
	if len(sig) == 65 {
		sig = sig[:64]
	}
	return ethcrypto.VerifySignature(ethcrypto.CompressPubkey(&pk.ecdsa), message[:], sig)
}

// Bytes returns the byte representation of the public key
func (pk PublicKey) Bytes() []byte {
	return ethcrypto.CompressPubkey(&pk.ecdsa)
}

func (pk PublicKey) UncompressedBytes() []byte {
	return append(pk.ecdsa.X.Bytes(), pk.ecdsa.Y.Bytes()...)
}

// PublicKeyFromBytes create a public key from []byte
func PublicKeyFromBytes(keyBytes []byte) (crypto.PublicKey, error) {
	switch len(keyBytes) {
	case 65:
		rpk, err := ethcrypto.UnmarshalPubkey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("could not convert pk: %w", err)
		}

		return &PublicKey{ecdsa: *rpk}, nil
	case 64:
		rpk, err := ethcrypto.UnmarshalPubkey(append([]byte{byte(4)}, keyBytes...))
		if err != nil {
			return nil, fmt.Errorf("could not convert pk: %w", err)
		}

		return &PublicKey{ecdsa: *rpk}, nil
	case 33:
		pk, err := ethcrypto.DecompressPubkey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("could not decompress pk: %w", err)
		}

		return &PublicKey{ecdsa: *pk}, nil
	default:
		return nil, fmt.Errorf("invalid key length %v", len(keyBytes))
	}
}

// ECIES returns an ECIES representation of the public key.
func (pk PublicKey) ECIES() (*ecies.PublicKey, error) {
	return ecies.ImportECDSAPublic(&pk.ecdsa), nil
}

func (pk PublicKey) ECDSA() *ecdsa.PublicKey {
	return &pk.ecdsa
}
