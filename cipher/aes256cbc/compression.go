package aes256cbc

import (
	"crypto/elliptic"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const (
	pubKeyBytesLenCompressed   = 33
	pubKeyBytesLenUncompressed = 65
	compressedKeyPrefix        = 4
)

// compress a 65 byte uncompressed public key
func compress(publicKey []byte) ([]byte, error) {
	if len(publicKey) == pubKeyBytesLenUncompressed-1 && publicKey[0] != compressedKeyPrefix {
		publicKey = append([]byte{compressedKeyPrefix}, publicKey...)
	}
	if len(publicKey) != pubKeyBytesLenUncompressed {
		return nil, fmt.Errorf("length of uncompressed public key is invalid")
	}
	x, y := elliptic.Unmarshal(ecies.DefaultCurve, publicKey)

	return secp256k1.CompressPubkey(x, y), nil
}

// decompress a 33 byte compressed public key
func decompress(publicKey []byte) []byte {
	x, y := secp256k1.DecompressPubkey(publicKey)
	return elliptic.Marshal(ecies.DefaultCurve, x, y)
}
