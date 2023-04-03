package crypto

const (
	// KindSECP256K1 string identifier for secp256k1 keys.
	KindSECP256K1 = "secp256k1"
	// KindSECP256R1 string identifier for secp256r1 keys.
	KindSECP256R1 = "secp256r1"
	// KindED25519 string identifier for ed25519 keys.
	KindED25519 = "ed25519"
	// KindSR25519 string identifier for sr25519 keys.
	KindSR25519 = "sr25519"
)

const (
	// IDUnknown byte identifier for unknown keys.
	IDUnknown = 0x0
	// IDSECP256K1 byte identifier for secp256k1 keys.
	IDSECP256K1 = 0xe1
	// IDED25519 byte identifier for ed25519 keys.
	IDED25519 = 0xe2
	// IDSR25519 byte identifier for sr25519 keys.
	IDSR25519 = 0xe3
	// IDSECP256R1 Id identifier for secp256r1 keys.
	IDSECP256R1 = 0xe4
	// IDNonSpecified Id identifier for non specified secret keys.
	IDNonSpecified = 0xee
)

var CurveKindIDMapping = map[string]byte{ //nolint:gochecknoglobals
	KindSECP256K1: IDSECP256K1,
	KindED25519:   IDED25519,
	KindSR25519:   IDSR25519,
	KindSECP256R1: IDSECP256R1,
}

// KeyTypes available key types.
func KeyTypes() map[string]bool {
	return map[string]bool{
		KindSECP256K1: true,
		KindED25519:   true,
		KindSR25519:   true,
		KindSECP256R1: true,
	}
}
