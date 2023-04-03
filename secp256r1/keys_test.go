package secp256r1

import (
	"crypto/ecdsa"
	"log"

	"github.com/mailchain/go-encoding/encodingtest"
)

var (
	aliceSECP256R1PrivateKey = func() PrivateKey {
		k, err := PrivateKeyFromBytes(aliceSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *k
	}() //nolint: lll

	aliceSECP256R1PrivateKeyBytes = encodingtest.MustDecodeHex("3cdee0ff28337463455cd1cc43d29b1bf749d9615576525853ccc02b83c8b433")

	aliceSECP256R1PrivateECDSA = func() ecdsa.PrivateKey {
		key, err := toECDSA(aliceSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *key
	}

	aliceSECP256R1PublicKey = func() PublicKey {
		k, err := PublicKeyFromBytes(aliceSECP256R1PublicKeyBytes)
		if err != nil {
			log.Fatal(err)
		}

		return *k.(*PublicKey)
	}()
	aliceSECP256R1PublicKeyBytes = encodingtest.MustDecodeHex("0330ef59d5da4547c684aa0d5b7d8c1527fceab462cfd8d4a3529319c469b0d4d7")
)

var (
	bobSECP256R1PrivateKey = func() PrivateKey {
		k, err := PrivateKeyFromBytes(bobSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *k
	}() //nolint: lll

	bobSECP256R1PrivateKeyBytes = encodingtest.MustDecodeHex("a1e65c4677435cea57950b39379a9ec7ec0c64edc97efe36cdaae3c386fe2b71")

	bobSECP256R1PrivateECDSA = func() ecdsa.PrivateKey {
		key, err := toECDSA(bobSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *key
	}
	bobSECP256R1PublicKey = func() PublicKey {
		k, err := PublicKeyFromBytes(bobSECP256R1PublicKeyBytes)
		if err != nil {
			log.Fatal(err)
		}

		return *k.(*PublicKey)
	}()
	bobSECP256R1PublicKeyBytes = encodingtest.MustDecodeHex("032da43f4b992968e53c68c894933e8ba22a7905bf9cdc903fd96d4f38ff49e115")
)

var (
	carlosSECP256R1PrivateKey = func() PrivateKey {
		k, err := PrivateKeyFromBytes(carlosSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *k
	}() //nolint: lll

	carlosSECP256R1PrivateKeyBytes = encodingtest.MustDecodeHex("7198ec54092518b49b2c66468a058f1fdbf0fdf0b1e281a027c692bb0ee1d1ed")
	carlosSECP256R1PrivateECDSA    = func() ecdsa.PrivateKey {
		key, err := toECDSA(carlosSECP256R1PrivateKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return *key
	}
	carlosSECP256R1PublicKey = func() PublicKey {
		k, err := PublicKeyFromBytes(carlosSECP256R1PublicKeyBytes)
		if err != nil {
			log.Fatal(err)
		}

		return *k.(*PublicKey)
	}()
	carlosSECP256R1PublicKeyBytes = encodingtest.MustDecodeHex("02c48a6a32004a6ec31b78c05c9ea9d6bee0904f7f7a13f384c6f2a25c86fcb0e6")
)
