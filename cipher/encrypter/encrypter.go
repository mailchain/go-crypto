package encrypter

import (
	"fmt"

	keys "github.com/mailchain/go-crypto"
	crypto "github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/cipher/aes256cbc"
	"github.com/mailchain/go-crypto/cipher/nacl"
	"github.com/mailchain/go-crypto/cipher/noop"
)

// Cipher Name lookup
const (
	// NoOperation encryption type name.
	NoOperation string = "noop"
	// NACL encryption type name.
	NACLECDH string = "nacl-ecdh"
	// AES256CBC encryption type name.
	AES256CBC string = "aes256cbc"
)

// GetEncrypter is an `Encrypter` factory that returns an encrypter
func GetEncrypter(encryption string, pubKey keys.PublicKey) (crypto.Encrypter, error) {
	switch encryption {
	case AES256CBC:
		return aes256cbc.NewEncrypter(pubKey)
	case NACLECDH:
		return nacl.NewPublicKeyEncrypter(pubKey)
	case NoOperation:
		return noop.NewEncrypter(pubKey)
	case "":
		return nil, fmt.Errorf("`encryption` provided is set to empty")
	default:
		return nil, fmt.Errorf("`encryption` provided is invalid")
	}
}
