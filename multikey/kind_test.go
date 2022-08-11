package multikey

import (
	"testing"

	"github.com/mailchain/mailchain/crypto/sr25519/sr25519test"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/stretchr/testify/assert"
)

func TestKeyKindFromSignature(t *testing.T) {
	type args struct {
		pubKey  []byte
		message []byte
		sig     []byte
		kinds   []string
	}
	tests := []struct {
		name    string
		args    args
		wantKey crypto.PublicKey
		wantErr error
	}{
		{
			"success-ed25519-duplicate-key-kinds",
			args{
				ed25519test.AlicePublicKey.Bytes(),
				[]byte("egassem"),
				[]byte{0xde, 0x6c, 0x88, 0xe6, 0x9c, 0x9f, 0x93, 0xb, 0x59, 0xdd, 0xf4, 0x80, 0xc2, 0x9a, 0x55, 0x79, 0xec, 0x89, 0x5c, 0xa9, 0x7a, 0x36, 0xf6, 0x69, 0x74, 0xc1, 0xf0, 0x15, 0x5c, 0xc0, 0x66, 0x75, 0x2e, 0xcd, 0x9a, 0x9b, 0x41, 0x35, 0xd2, 0x72, 0x32, 0xe0, 0x54, 0x80, 0xbc, 0x98, 0x58, 0x1, 0xa9, 0xfd, 0xe4, 0x27, 0xc7, 0xef, 0xa5, 0x42, 0x5f, 0xf, 0x46, 0x49, 0xb8, 0xad, 0xbd, 0x5},
				[]string{crypto.KindED25519, crypto.KindED25519, crypto.KindED25519},
			},
			ed25519test.AlicePublicKey,
			nil,
		},
		{
			"success-secp256k1-duplicate-key-kinds",
			args{
				secp256k1test.AlicePublicKey.Bytes(),
				[]byte("egassem"),
				[]byte{0xe9, 0x33, 0xe, 0x4a, 0xe3, 0x5, 0x19, 0xea, 0x36, 0x37, 0x19, 0xdd, 0xbc, 0x91, 0xfd, 0x4f, 0xd3, 0x64, 0x9b, 0xdc, 0xf0, 0x74, 0x36, 0x16, 0xc9, 0x81, 0xfc, 0x6d, 0x3c, 0x7e, 0xb0, 0xd0, 0x6e, 0xdd, 0x4, 0x13, 0xfd, 0x15, 0xe5, 0xec, 0x64, 0x6e, 0x63, 0xe0, 0x84, 0xdb, 0xb2, 0xd7, 0xcf, 0x18, 0x3d, 0x81, 0x1e, 0x31, 0x36, 0x77, 0x39, 0x86, 0x4b, 0x58, 0xb8, 0x23, 0xed, 0xc, 0x1},
				[]string{crypto.KindSECP256K1, crypto.KindSECP256K1},
			},
			secp256k1test.AlicePublicKey,
			nil,
		},
		{
			"success-ed25519-alice-key",
			args{
				ed25519test.AlicePublicKey.Bytes(),
				[]byte("egassem"),
				[]byte{0xde, 0x6c, 0x88, 0xe6, 0x9c, 0x9f, 0x93, 0xb, 0x59, 0xdd, 0xf4, 0x80, 0xc2, 0x9a, 0x55, 0x79, 0xec, 0x89, 0x5c, 0xa9, 0x7a, 0x36, 0xf6, 0x69, 0x74, 0xc1, 0xf0, 0x15, 0x5c, 0xc0, 0x66, 0x75, 0x2e, 0xcd, 0x9a, 0x9b, 0x41, 0x35, 0xd2, 0x72, 0x32, 0xe0, 0x54, 0x80, 0xbc, 0x98, 0x58, 0x1, 0xa9, 0xfd, 0xe4, 0x27, 0xc7, 0xef, 0xa5, 0x42, 0x5f, 0xf, 0x46, 0x49, 0xb8, 0xad, 0xbd, 0x5},
				[]string{crypto.KindED25519},
			},
			ed25519test.AlicePublicKey,
			nil,
		},
		{
			"success-secp256k1-alice-key",
			args{
				secp256k1test.AlicePublicKey.Bytes(),
				[]byte("egassem"),
				[]byte{0xe9, 0x33, 0xe, 0x4a, 0xe3, 0x5, 0x19, 0xea, 0x36, 0x37, 0x19, 0xdd, 0xbc, 0x91, 0xfd, 0x4f, 0xd3, 0x64, 0x9b, 0xdc, 0xf0, 0x74, 0x36, 0x16, 0xc9, 0x81, 0xfc, 0x6d, 0x3c, 0x7e, 0xb0, 0xd0, 0x6e, 0xdd, 0x4, 0x13, 0xfd, 0x15, 0xe5, 0xec, 0x64, 0x6e, 0x63, 0xe0, 0x84, 0xdb, 0xb2, 0xd7, 0xcf, 0x18, 0x3d, 0x81, 0x1e, 0x31, 0x36, 0x77, 0x39, 0x86, 0x4b, 0x58, 0xb8, 0x23, 0xed, 0xc, 0x1},
				[]string{crypto.KindSECP256K1},
			},
			secp256k1test.AlicePublicKey,
			nil,
		},
		{
			"success-ed25519-bob-key",
			args{
				ed25519test.BobPublicKey.Bytes(),
				[]byte("message"),
				[]byte{0x7d, 0x51, 0xea, 0xfa, 0x52, 0x78, 0x31, 0x69, 0xd0, 0xa9, 0x4a, 0xc, 0x9f, 0x2b, 0xca, 0xd5, 0xe0, 0x3d, 0x29, 0x17, 0x33, 0x0, 0x93, 0xf, 0xf3, 0xc7, 0xd6, 0x3b, 0xfd, 0x64, 0x17, 0xae, 0x1b, 0xc8, 0x1f, 0xef, 0x51, 0xba, 0x14, 0x9a, 0xe8, 0xa1, 0xe1, 0xda, 0xe0, 0x5f, 0xdc, 0xa5, 0x7, 0x8b, 0x14, 0xba, 0xc4, 0xcf, 0x26, 0xcc, 0xc6, 0x1, 0x1e, 0x5e, 0xab, 0x77, 0x3, 0xc},
				[]string{crypto.KindED25519},
			},
			ed25519test.BobPublicKey,
			nil,
		},
		{
			"success-secp256k1-bob-key",
			args{
				secp256k1test.BobPublicKey.Bytes(),
				[]byte("message"),
				[]byte{0x9d, 0xf7, 0x76, 0xab, 0xde, 0x8c, 0x20, 0x55, 0xc3, 0x4, 0x68, 0x37, 0xa8, 0x66, 0xf8, 0x89, 0x95, 0xf9, 0x82, 0xf0, 0x4b, 0xb8, 0x23, 0x40, 0xf0, 0x3, 0x8, 0x6a, 0x32, 0xa7, 0xac, 0xef, 0x5f, 0xa, 0xea, 0xda, 0x60, 0xbf, 0x9, 0xd5, 0xc3, 0x27, 0x61, 0xa, 0xc5, 0xc8, 0x33, 0xe3, 0xa0, 0x79, 0xdf, 0x6d, 0xe1, 0x9c, 0xa8, 0xcc, 0x33, 0xea, 0x1d, 0xe6, 0x3, 0x34, 0xb1, 0xa1, 0x0},
				[]string{crypto.KindSECP256K1},
			},
			secp256k1test.BobPublicKey,
			nil,
		},
		{
			"success-ed25519-mix-key-kinds",
			args{
				ed25519test.AlicePublicKey.Bytes(),
				[]byte("egassem"),
				[]byte{0xde, 0x6c, 0x88, 0xe6, 0x9c, 0x9f, 0x93, 0xb, 0x59, 0xdd, 0xf4, 0x80, 0xc2, 0x9a, 0x55, 0x79, 0xec, 0x89, 0x5c, 0xa9, 0x7a, 0x36, 0xf6, 0x69, 0x74, 0xc1, 0xf0, 0x15, 0x5c, 0xc0, 0x66, 0x75, 0x2e, 0xcd, 0x9a, 0x9b, 0x41, 0x35, 0xd2, 0x72, 0x32, 0xe0, 0x54, 0x80, 0xbc, 0x98, 0x58, 0x1, 0xa9, 0xfd, 0xe4, 0x27, 0xc7, 0xef, 0xa5, 0x42, 0x5f, 0xf, 0x46, 0x49, 0xb8, 0xad, 0xbd, 0x5},
				[]string{crypto.KindED25519, crypto.KindSECP256K1},
			},
			ed25519test.AlicePublicKey,
			nil,
		},
		{
			"success-secp256k1-mix-key-kinds",
			args{
				secp256k1test.BobPublicKey.Bytes(),
				[]byte("message"),
				[]byte{0x9d, 0xf7, 0x76, 0xab, 0xde, 0x8c, 0x20, 0x55, 0xc3, 0x4, 0x68, 0x37, 0xa8, 0x66, 0xf8, 0x89, 0x95, 0xf9, 0x82, 0xf0, 0x4b, 0xb8, 0x23, 0x40, 0xf0, 0x3, 0x8, 0x6a, 0x32, 0xa7, 0xac, 0xef, 0x5f, 0xa, 0xea, 0xda, 0x60, 0xbf, 0x9, 0xd5, 0xc3, 0x27, 0x61, 0xa, 0xc5, 0xc8, 0x33, 0xe3, 0xa0, 0x79, 0xdf, 0x6d, 0xe1, 0x9c, 0xa8, 0xcc, 0x33, 0xea, 0x1d, 0xe6, 0x3, 0x34, 0xb1, 0xa1, 0x0},
				[]string{crypto.KindSECP256K1, crypto.KindED25519},
			},
			secp256k1test.BobPublicKey,
			nil,
		},
		{
			"err-invalid-public-key-bytes",
			args{
				[]byte{0x1},
				[]byte("unknown"),
				nil,
				[]string{crypto.KindED25519, crypto.KindSECP256K1},
			},
			nil,
			ErrNoMatch,
		},
		{
			"err-no-key-kinds",
			args{
				secp256k1test.BobPublicKey.Bytes(),
				[]byte("message"),
				[]byte{0x9d, 0xf7, 0x76, 0xab, 0xde, 0x8c, 0x20, 0x55, 0xc3, 0x4, 0x68, 0x37, 0xa8, 0x66, 0xf8, 0x89, 0x95, 0xf9, 0x82, 0xf0, 0x4b, 0xb8, 0x23, 0x40, 0xf0, 0x3, 0x8, 0x6a, 0x32, 0xa7, 0xac, 0xef, 0x5f, 0xa, 0xea, 0xda, 0x60, 0xbf, 0x9, 0xd5, 0xc3, 0x27, 0x61, 0xa, 0xc5, 0xc8, 0x33, 0xe3, 0xa0, 0x79, 0xdf, 0x6d, 0xe1, 0x9c, 0xa8, 0xcc, 0x33, 0xea, 0x1d, 0xe6, 0x3, 0x34, 0xb1, 0xa1, 0x0},
				nil,
			},
			nil,
			ErrNoMatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := KeyKindFromSignature(tt.args.pubKey, tt.args.message, tt.args.sig, tt.args.kinds)

			if !(err == tt.wantErr) {
				t.Errorf("KeyKindFromSignature() err = %v, want %v", err, tt.wantErr)
			}

			if !assert.Equal(t, key, tt.wantKey) {
				t.Errorf("KeyKindFromSignature() key = %v, want %v", key, tt.wantKey)
			}
		})
	}
}

func TestGetKeyKindFromBytes(t *testing.T) {
	type args struct {
		publicKey  []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantKey crypto.PrivateKey
		wantErr error
	}{
		{
			name: "success-ed25519-alice-key",
			args: args{
				publicKey:  ed25519test.AlicePublicKey.Bytes(),
				privateKey: ed25519test.AlicePrivateKey.Bytes(),
			},
			wantKey: ed25519test.AlicePrivateKey,
		},
		{
			name: "success-ed25519-bob-key",
			args: args{
				publicKey:  ed25519test.BobPublicKey.Bytes(),
				privateKey: ed25519test.BobPrivateKey.Bytes(),
			},
			wantKey: ed25519test.BobPrivateKey,
		},
		{
			name: "success-secp256k1-alice-key",
			args: args{
				publicKey:  secp256k1test.AlicePublicKey.Bytes(),
				privateKey: secp256k1test.AlicePrivateKey.Bytes(),
			},
			wantKey: secp256k1test.AlicePrivateKey,
		},
		{
			name: "success-secp256k1-bob-key",
			args: args{
				publicKey:  secp256k1test.BobPublicKey.Bytes(),
				privateKey: secp256k1test.BobPrivateKey.Bytes(),
			},
			wantKey: secp256k1test.BobPrivateKey,
		},
		{
			name: "success-sr25519-alice-key",
			args: args{
				publicKey:  sr25519test.AlicePublicKey.Bytes(),
				privateKey: sr25519test.AlicePrivateKey.Bytes(),
			},
			wantKey: sr25519test.AlicePrivateKey,
		},
		{
			name: "success-sr25519-bob-key",
			args: args{
				publicKey:  sr25519test.BobPublicKey.Bytes(),
				privateKey: sr25519test.BobPrivateKey.Bytes(),
			},
			wantKey: sr25519test.BobPrivateKey,
		},
		{
			name: "err-invalid-public-key-bytes",
			args: args{
				publicKey:  []byte{0x1},
				privateKey: sr25519test.BobPrivateKey.Bytes(),
			},
			wantErr: ErrNoMatch,
		},
		{
			name: "err-no-key-kinds",
			args: args{
				publicKey:  []byte{0x1},
				privateKey: []byte{0x2},
			},
			wantErr: ErrNoMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GetKeyKindFromBytes(tt.args.publicKey, tt.args.privateKey)

			if !(err == tt.wantErr) {
				t.Errorf("GetKeyKindFromBytes() err = %v, want %v", err, tt.wantErr)
			}

			if !assert.Equal(t, privateKey, tt.wantKey) {
				t.Errorf("GetKeyKindFromBytes() key = %v, want %v", privateKey, tt.wantKey)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{
			[]string{"x", "x", "y"},
			[]string{"x", "y"},
		},
		{
			nil,
			nil,
		},
		{
			[]string{},
			[]string{},
		},
		{
			[]string{"c", "a", "c"},
			[]string{"c", "a"},
		},
		{
			[]string{"d", "a", "f", "a", "e", "e", "z", "f", "t"},
			[]string{"d", "a", "f", "e", "z", "t"},
		},
	}
	for _, tt := range tests {
		t.Run("remove-duplicates", func(t *testing.T) {
			got := removeDuplicates(tt.in)
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("removeDuplicates() = %v, want %v", got, tt.want)
			}
		})
	}
}
