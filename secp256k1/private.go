package secp256k1

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/mailchain/go-crypto"
)

var (

	// ErrUnusableSeed describes an error in which the provided seed is not
	// usable due to the derived key falling outside of the valid range for
	// secp256k1 private keys.  This error indicates the caller must choose
	// another seed.
	ErrUnusableSeed = errors.New("unusable seed")
)

// PrivateKey based on the secp256k1 curve.
type PrivateKey struct {
	ecdsa ecdsa.PrivateKey
}

// Bytes returns the byte representation of the private key.
func (pk PrivateKey) Bytes() []byte {
	return ethcrypto.FromECDSA(&pk.ecdsa)
}

// TODO: remove this sign function
// Sign signs the message with the private key and returns the signature.
func (pk PrivateKey) Sign(message []byte) (signature []byte, err error) {
	return ethcrypto.Sign(message[:], &pk.ecdsa)
}

// PublicKey return the public key that is derived from the private key.
func (pk PrivateKey) PublicKey() crypto.PublicKey {
	return &PublicKey{ecdsa: pk.ecdsa.PublicKey}
}

// ECIES returns an ECIES representation of the private key.
func (pk PrivateKey) ECIES() *ecies.PrivateKey {
	return ecies.ImportECDSA(&pk.ecdsa)
}

// ECDSA returns an ECDSA representation of the private key.
func (pk PrivateKey) ECDSA() (*ecdsa.PrivateKey, error) {
	rpk, err := ethcrypto.ToECDSA(pk.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not convert private key: %w", err)
	}
	return rpk, nil
}

// PrivateKeyFromECDSA get a private key from an ecdsa.PrivateKey.
func PrivateKeyFromECDSA(pk ecdsa.PrivateKey) PrivateKey {
	return PrivateKey{ecdsa: pk}
}

// PrivateKeyFromBytes get a private key from []byte.
func PrivateKeyFromBytes(pk []byte) (*PrivateKey, error) {
	// Ensure the private key is valid.  It must be within the range
	// of the order of the secp256k1 curve and not be 0.
	keyNum := new(big.Int).SetBytes(pk)
	if keyNum.Cmp(ethcrypto.S256().Params().N) >= 0 || keyNum.Sign() == 0 {
		return nil, ErrUnusableSeed
	}

	rpk, err := ethcrypto.ToECDSA(pk)
	if err != nil {
		return nil, fmt.Errorf("could not convert private key")
	}

	return &PrivateKey{ecdsa: *rpk}, nil
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	pk, err := ecdsa.GenerateKey(ethcrypto.S256(), rand)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{ecdsa: *pk}, nil
}
