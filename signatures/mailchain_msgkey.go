package signatures

import (
	"fmt"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519"
	"github.com/mailchain/mailchain/crypto/multikey"
	"github.com/mailchain/mailchain/encoding"
)

var (
	errAddressEmpty  = fmt.Errorf("address must be supplied")
	errProtocolEmpty = fmt.Errorf("protocol must be supplied")
)

func mailchainProvidedMessagingKeyMessage(msgKey crypto.PublicKey, address, protocol string) ([]byte, error) {
	if address == "" {
		return nil, errAddressEmpty
	}
	if protocol == "" {
		return nil, errProtocolEmpty
	}

	switch msgKey.(type) {
	case *ed25519.PublicKey:
		descriptiveKey, err := multikey.DescriptiveBytesFromPublicKey(msgKey)
		if err != nil {
			return nil, err
		}

		encodedKey := encoding.EncodeHexZeroX(descriptiveKey)

		return []byte(fmt.Sprintf("\x11Mailchain provided messaging key:\nAddress:%s\nProtocol:%s\nKey:%s", address, protocol, encodedKey)), nil
	default:
		return nil, ErrKeyNotSupported
	}
}

// SignMailchainProvidedMessagingKey signs a Mailchian provided messaging key signed by the Mailchain master messaging private key.
func SignMailchainProvidedMessagingKey(key crypto.PrivateKey, msgKey crypto.PublicKey, address string, protocol string) ([]byte, error) {
	switch pk := key.(type) {
	case *ed25519.PrivateKey:
		msg, err := mailchainProvidedMessagingKeyMessage(msgKey, address, protocol)
		if err != nil {
			return nil, err
		}

		return pk.Sign(msg)
	default:
		return nil, ErrKeyNotSupported
	}
}

// VerifyMailchainProvidedMessagingKey verifies a messaging key is provided by Mailchain.
func VerifyMailchainProvidedMessagingKey(key crypto.PublicKey, signature []byte, msgKey crypto.PublicKey, address string, protocol string) (bool, error) {
	switch pk := key.(type) {
	case *ed25519.PublicKey:
		msg, err := mailchainProvidedMessagingKeyMessage(msgKey, address, protocol)
		if err != nil {
			return false, err
		}

		return pk.Verify(msg, signature), nil
	default:
		return false, ErrKeyNotSupported
	}
}
