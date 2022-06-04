package signatures

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto"
)

func Verifiy(signingMethod string, verifyingKey crypto.PublicKey, message []byte, signature []byte) (bool, error) {
	switch signingMethod {
	case KindEthereumPersonalMessage:
		return VerifyEthereumPersonalMessage(verifyingKey, message, signature)
	case KindRawED25519:
		return VerifyRawED25519(verifyingKey, message, signature)
	default:
		return false, fmt.Errorf("unsupported signing method %s", signingMethod)
	}
}
