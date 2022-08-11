//go:generate mockgen -source=private.go -package=cryptotest -destination=./cryptotest/private_mock.go
package crypto

// PrivateKey definition usable in all mailchain crypto operations
type PrivateKey interface {
	// Bytes returns the byte representation of the private key
	Bytes() []byte
	// PublicKey from the PrivateKey
	PublicKey() PublicKey
	// Sign signs the message with the key and returns the signature.
	Sign(message []byte) ([]byte, error)
}

type ExtendedPrivateKey interface {
	Bytes() []byte
	PrivateKey() PrivateKey
	Derive(index uint32) (ExtendedPrivateKey, error)
	ExtendedPublicKey() (ExtendedPublicKey, error)
}
