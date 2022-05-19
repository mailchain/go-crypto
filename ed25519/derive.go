package ed25519

import (
	"github.com/mailchain/mailchain/crypto"
	"github.com/minio/blake2b-simd"
)

var hdkd = []byte{44, 69, 100, 50, 53, 53, 49, 57, 72, 68, 75, 68} //Ed25519HDKD prefix compatible with polkadot HDKD

func DeriveHardenedKey(parent crypto.PrivateKey, chaincode []byte) (*PrivateKey, error) {
	val := append(hdkd, parent.Bytes()...)
	val = append(val, chaincode...)

	seed := blake2b.Sum256(val)

	return PrivateKeyFromBytes(seed[:])
}
