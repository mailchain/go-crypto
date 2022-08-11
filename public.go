//go:generate mockgen -source=public.go -package=cryptotest -destination=./cryptotest/public_mock.go
package crypto

// PublicKey definition usable in all mailchain crypto operations
type PublicKey interface {
	// Bytes returns the raw bytes representation of the public key.
	//
	// The returned bytes are used for encrypting, verifying a signature, and locating an address.
	Bytes() []byte
	// Verify verifies whether sig is a valid signature of message.
	Verify(message, sig []byte) bool
}

type ExtendedPublicKey interface {
	Bytes() []byte
	PublicKey() PublicKey
	Derive(index uint32) (ExtendedPublicKey, error)
}
