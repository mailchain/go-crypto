package ed25519

import (
	"errors"

	"github.com/mailchain/mailchain/crypto"
	"github.com/minio/blake2b-simd"
)

var hdkd = []byte{44, 69, 100, 50, 53, 53, 49, 57, 72, 68, 75, 68} //Ed25519HDKD prefix compatible with polkadot HDKD

func DeriveHardenedKey(parent crypto.PrivateKey, chaincode []byte) (*PrivateKey, error) {
	parentSeed, err := seedBytes(parent)
	if err != nil {
		return nil, err
	}

	val := append(hdkd, parentSeed...)
	val = append(val, chaincode...)

	childSeed := blake2b.Sum256(val)

	return PrivateKeyFromBytes(childSeed[:])
}

func seedBytes(parent crypto.PrivateKey) ([]byte, error) {
	switch edKey := parent.(type) {
	case *PrivateKey:
		return edKey.Key.Seed(), nil
	default:
		return nil, errors.New("unknown private key type")
	}

}
