package aes256cbc

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/secp256k1"
)

func asPublicECIES(pk crypto.PublicKey) (*ecies.PublicKey, error) {
	switch rpk := pk.(type) {
	case *secp256k1.PublicKey:
		return rpk.ECIES()
	case secp256k1.PublicKey:
		return rpk.ECIES()
	default:
		return nil, fmt.Errorf("could not convert public key")
	}
}
func asPrivateECIES(pk crypto.PrivateKey) (*ecies.PrivateKey, error) {
	switch rpk := pk.(type) {
	case *secp256k1.PrivateKey:
		return rpk.ECIES(), nil
	case secp256k1.PrivateKey:
		return rpk.ECIES(), nil
	default:
		return nil, fmt.Errorf("could not convert private key")
	}
}
