package signatures

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/encoding"
)

func mailchainDeliveryConfirmationMessage(deliveryRequestID []byte) []byte {
	return []byte(fmt.Sprintf("\x11Mailchain delivery confirmation:\n%s", encoding.EncodeHex(deliveryRequestID)))
}

// SignMailchainDeliveryConfirmation signs a message using the Mailchain username with the identity private key.
func SignMailchainDeliveryConfirmation(key crypto.PrivateKey, deliveryRequestID []byte) ([]byte, error) {
	switch pk := key.(type) {
	case *ed25519.PrivateKey:
		msg := mailchainDeliveryConfirmationMessage(deliveryRequestID)

		return pk.Sign(msg)
	default:
		return nil, ErrKeyNotSupported
	}
}

// VerifyMailchainDeliveryConfirmation verifies a message linking a username with an identity key is valid.
func VerifyMailchainDeliveryConfirmation(key crypto.PublicKey, deliveryRequestID, signature []byte) (bool, error) {
	switch pk := key.(type) {
	case *ed25519.PublicKey:
		msg := mailchainDeliveryConfirmationMessage(deliveryRequestID)

		return pk.Verify(msg, signature), nil
	default:
		return false, ErrKeyNotSupported
	}
}
