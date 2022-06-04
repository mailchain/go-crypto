package signatures

const (
	KindEthereumPersonalMessage = "ethereum_personal_message"
	// KindRawED25519 signs the message with the curve's native sign method with no pre-processing.
	KindRawED25519                   = "raw_ed25519"
	KindMailchainUsernameIdentityKey = "mailchain_username_identity_key"
)
