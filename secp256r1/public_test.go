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
				sig:     encodingtest.MustDecodeHex("e77fedf8e6c381a5578b6a18af80b5758453a5f9c34c5322fb4ff3a56db8b86155280610b5d061da74cc6b07bcfca7cbbe00a645fe4d79e2b1442ab2d0ac35a6"),
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
				sig:     encodingtest.MustDecodeHex("de5db37e848e34fc4a9999410969edb4ed20676a7209754968bbcf289ac2efc23fabad06e7fa69bbb01f5de0b9f6e19d95fd1f2ab5c03687ae6c83ab965e6787"),
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
				sig:     encodingtest.MustDecodeHex("59cd7012db33304d04ee9f10f07aa32c3dd482268fd9e5dcb031ecaf17af532c2768b481f74653e425fc2ac3ff73a72782fc0dc4855578887e187b68027229d1"),
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
