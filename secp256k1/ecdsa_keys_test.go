package secp256k1

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

func ecdsaPrivateKeyAlice() ecdsa.PrivateKey {
	b, _ := hex.DecodeString("01901E63389EF02EAA7C5782E08B40D98FAEF835F28BD144EECF5614A415943F")
	key, err := crypto.ToECDSA(b)
	if err != nil {
		log.Fatal(err)
	}
	return *key
}

func ecdsaPublicKeyAlice() ecdsa.PublicKey {
	return ecdsaPrivateKeyAlice().PublicKey
}

func ecdsaPrivateKeyBob() ecdsa.PrivateKey {
	b, _ := hex.DecodeString("DF4BA9F6106AD2846472F759476535E55C5805D8337DF5A11C3B139F438B98B3")
	key, err := crypto.ToECDSA(b)
	if err != nil {
		log.Fatal(err)
	}
	return *key
}

func ecdsaPublicKeyBob() ecdsa.PublicKey {
	return ecdsaPrivateKeyBob().PublicKey
}
