package signatures

import (
	"github.com/ethereum/go-ethereum/accounts"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/secp256k1"
)

func SignEthereumPersonalMessage(key crypto.PrivateKey, message []byte) ([]byte, error) {
	switch pk := key.(type) {
	case *secp256k1.PrivateKey:
		ecdsa, err := pk.ECDSA()
		if err != nil {
			return nil, err
		}

		hash, _ := accounts.TextAndHash(message)

		sig, err := ethcrypto.Sign(hash[:], ecdsa)
		if err != nil {
			return nil, err
		}

		sig[64] += 27

		return sig, nil
	default:
		return nil, ErrKeyNotSupported
	}
}
