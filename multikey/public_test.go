package multikey

import (
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/ed25519/ed25519test"
	"github.com/mailchain/go-crypto/secp256k1/secp256k1test"
	"github.com/mailchain/go-crypto/sr25519/sr25519test"
	"github.com/stretchr/testify/assert"
)

func TestPublicKeyFromBytes(t *testing.T) {
	type args struct {
		hex     string
		keyType []byte
	}
	tests := []struct {
		name      string
		args      args
		wantBytes []byte
		wantErr   bool
	}{
		{
			"secp256k1",
			args{
				"secp256k1",
				secp256k1test.AlicePublicKey.Bytes(),
			},
			secp256k1test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"ed25519",
			args{
				"ed25519",
				ed25519test.AlicePublicKey.Bytes(),
			},
			ed25519test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"sr25519",
			args{
				"sr25519",
				sr25519test.AlicePublicKey.Bytes(),
			},
			sr25519test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"err",
			args{
				"unknown",
				secp256k1test.AlicePublicKey.Bytes(),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicKeyFromBytes(tt.args.hex, tt.args.keyType)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != nil {
				if !assert.EqualValues(t, tt.wantBytes, got.Bytes()) {
					t.Errorf("PublicKeyFromBytes() = %v, want %v", got, tt.wantBytes)
				}
			}
			if got == nil {
				if !assert.Nil(t, tt.wantBytes) {
					t.Errorf("PublicKeyFromBytes() = %v, want %v", got, tt.wantBytes)
				}
			}

		})
	}
}

func TestDescriptivePublicKeyFromBytes(t *testing.T) {
	type args struct {
		in []byte
	}
	tests := []struct {
		name      string
		args      args
		wantBytes []byte
		wantErr   bool
	}{
		{
			"secp256k1",
			args{
				append([]byte{crypto.IDSECP256K1}, secp256k1test.AlicePublicKey.Bytes()...),
			},
			secp256k1test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"ed25519",
			args{
				append([]byte{crypto.IDED25519}, ed25519test.AlicePublicKey.Bytes()...),
			},
			ed25519test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"sr25519",
			args{
				append([]byte{crypto.IDSR25519}, sr25519test.AlicePublicKey.Bytes()...),
			},
			sr25519test.AlicePublicKey.Bytes(),
			false,
		},
		{
			"err",
			args{
				append([]byte{0x00}, sr25519test.AlicePublicKey.Bytes()...),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DescriptivePublicKeyFromBytes(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("DescriptivePublicKeyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if !assert.EqualValues(t, tt.wantBytes, got.Bytes()) {
					t.Errorf("DescriptivePublicKeyFromBytes() = %v, want %v", got, tt.wantBytes)
				}
			}
			if got == nil {
				if !assert.Nil(t, tt.wantBytes) {
					t.Errorf("DescriptivePublicKeyFromBytes() = %v, want %v", got, tt.wantBytes)
				}
			}
		})
	}
}

func TestDescriptiveBytesFromPublicKey(t *testing.T) {
	type args struct {
		in crypto.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1",
			args{
				secp256k1test.AlicePublicKey,
			},
			append([]byte{crypto.IDSECP256K1}, secp256k1test.AlicePublicKey.Bytes()...),
			assert.NoError,
		},
		{
			"ed25519",
			args{
				ed25519test.AlicePublicKey,
			},
			append([]byte{crypto.IDED25519}, ed25519test.AlicePublicKey.Bytes()...),
			assert.NoError,
		},
		{
			"sr25519",
			args{
				sr25519test.AlicePublicKey,
			},
			append([]byte{crypto.IDSR25519}, sr25519test.AlicePublicKey.Bytes()...),
			assert.NoError,
		},
		{
			"err",
			args{
				nil,
			},
			nil,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DescriptiveBytesFromPublicKey(tt.args.in)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
