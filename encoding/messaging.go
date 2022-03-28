package keys

import (
	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/multikey"
	"github.com/mailchain/mailchain/encoding"
)

// PrefixMsgKey creates a prefix of MsgKey that is used in front of the mesage key.
var PrefixMsgKey = []byte{0x1f, 0xf8, 0x39, 0xbf, 0x85, 0x99} //nolint: gochecknoglobals

// EncodeMessagingPublicKey encodes a public key with prefix that indicates it's purpose.
func EncodeMessagingPublicKey(key crypto.PublicKey) (string, error) {
	descriptiveKey, err := multikey.DescriptiveBytesFromPublicKey(key)
	if err != nil {
		return "", err
	}

	return encoding.EncodeBase58(append(PrefixMsgKey, descriptiveKey...)), nil
}
