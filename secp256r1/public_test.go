package secp256r1

import (
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-encoding/encodingtest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestPublicKey_Bytes(t *testing.T) {
	type args struct {
		key *PublicKey
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"alice",
			args{
				key: &aliceSECP256R1PublicKey,
			},
			aliceSECP256R1PublicKeyBytes,
		},
		{
			"bob",
			args{
				key: &bobSECP256R1PublicKey,
			},
			bobSECP256R1PublicKeyBytes,
		},
		{
			"carlos",
			args{
				key: &carlosSECP256R1PublicKey,
			},
			carlosSECP256R1PublicKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.args.key.Bytes(), tt.want)
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	type args struct {
		message []byte
		sig     []byte
	}
	tests := []struct {
		name   string
		target PublicKey
		args   args
		want   bool
	}{
		{
			"alice-success",
			aliceSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("ba1618aca63b24376e6f538beee4f757523081306ed10f301ada1a5919a5b68d526b2ae2f1cd8fd6985c42dd0fe681dc1d7e2ea091bc0c2e524de6d65f2c7318"),
			},
			true,
		},
		{
			"alice-success-ts-compatibility",
			aliceSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("3eb824015c1d13541ff6b6a5af1e64a7aa1d2e5fdc17c935a37d766616c307634eb97a751000158a88118f8ccfd43e9dd0eece2dcbdc0368b365fb8d51bf1d6c"),
			},
			true,
		},
		{
			"bob-success",
			bobSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("f3c5e4a924b18264c166d74f3210a1fbc42dd4d93b0d1b0f6a96ef6584ae31905d698badee1399287f4c3f49bca4a690a19ef95ce620aecc862cc1e4f8d0cdf1"),
			},
			true,
		},
		{
			"bob-success-ts-compatibility",
			bobSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("4b5c334e445a2b854b55918cde2be2b5a9ee4347bfa0261b76082774af8567c20d7c5c0134ed20619db380b063af3edbc75b3313532e210ad9943dbf419b9edd"),
			},
			true,
		},
		{
			"carlos-success",
			carlosSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("d6be4b13413fe3c1ca7562140a52ad14465f81d7a1ebc5eb74e3e5ef22126dfc25046c25ad5a09a67754161aed356a99a4b034e71aec36d714199c9e37485f56"),
			},
			true,
		},
		{
			"carlos-success-ts-compatibility",
			carlosSECP256R1PublicKey,
			args{
				message: []byte("hello from mailchain"),
				sig:     encodingtest.MustDecodeHex("8a7b2047bbb834a21f32ff5d1082c6810cdefbb4c7c28a037e59711866b2134306066ef68e9ec2f42b544736003771c21e318649274e1c10b766e032a9f3bdc2"),
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := tt.target
			digest := blake2b.Sum256(tt.args.message)
			assert.Equal(t, tt.want, pk.Verify(digest[:], tt.args.sig))
		})
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	type args struct {
		keyBytes []byte
	}
	tests := []struct {
		name      string
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			args{
				aliceSECP256R1PublicKeyBytes,
			},
			&aliceSECP256R1PublicKey,
			assert.NoError,
		},
		{
			"bob",
			args{
				bobSECP256R1PublicKeyBytes,
			},
			&bobSECP256R1PublicKey,
			assert.NoError,
		},
		{
			"carlos",
			args{
				carlosSECP256R1PublicKeyBytes,
			},
			&carlosSECP256R1PublicKey,
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicKeyFromBytes(tt.args.keyBytes)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
