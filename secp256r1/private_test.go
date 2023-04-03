package secp256r1

import (
	"crypto/ecdsa"
	"io"
	"strings"
	"testing"

	"github.com/mailchain/mailchain/testing/must"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestPrivateKeyFromBytes_Bytes(t *testing.T) {
	type args struct {
		privateKeyBytes []byte
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			args{aliceSECP256R1PrivateKeyBytes},
			aliceSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
		{
			"bob",
			args{bobSECP256R1PrivateKeyBytes},
			bobSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
		{
			"carlos",
			args{carlosSECP256R1PrivateKeyBytes},
			carlosSECP256R1PrivateKeyBytes,
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivateKeyFromBytes(tt.args.privateKeyBytes)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestPrivateKeyFromECDSA_Bytes(t *testing.T) {
	type fields struct {
		privateECDSAKey ecdsa.PrivateKey
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			"alice",
			fields{aliceSECP256R1PrivateECDSA()},
			aliceSECP256R1PrivateKeyBytes,
		},
		{
			"bob",
			fields{bobSECP256R1PrivateECDSA()},
			bobSECP256R1PrivateKeyBytes,
		},
		{
			"carlos",
			fields{carlosSECP256R1PrivateECDSA()},
			carlosSECP256R1PrivateKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PrivateKey{key: tt.fields.privateECDSAKey}
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestPrivateKey_PublicKey(t *testing.T) {
	tests := []struct {
		name   string
		target PrivateKey
		want   []byte
	}{
		{
			"alice",
			aliceSECP256R1PrivateKey,
			aliceSECP256R1PublicKeyBytes,
		},
		{
			"bob",
			bobSECP256R1PrivateKey,
			bobSECP256R1PublicKeyBytes,
		},
		{
			"carlos",
			carlosSECP256R1PrivateKey,
			carlosSECP256R1PublicKeyBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.PublicKey(); !assert.Equal(t, tt.want, got.Bytes()) {
				t.Errorf("PrivateKey.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_Sign(t *testing.T) {
	// because of MaybeReadByte in /opt/homebrew/Cellar/go@1.18/1.18.9/libexec/src/crypto/internal/randutil/randutil.go which applies a 50% probability to reading an extra byte
	// a zeroReader is required to consistently return the same value or a reader that returns the same bytes each time regardless of the first byte being read or not
	zeroReader := strings.NewReader("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	type fields struct {
		key  ecdsa.PrivateKey
		rand io.Reader
	}
	type args struct {
		message string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			fields{
				key:  aliceSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0xe7, 0x7f, 0xed, 0xf8, 0xe6, 0xc3, 0x81, 0xa5, 0x57, 0x8b, 0x6a, 0x18, 0xaf, 0x80, 0xb5, 0x75, 0x84, 0x53, 0xa5, 0xf9, 0xc3, 0x4c, 0x53, 0x22, 0xfb, 0x4f, 0xf3, 0xa5, 0x6d, 0xb8, 0xb8, 0x61, 0x55, 0x28, 0x6, 0x10, 0xb5, 0xd0, 0x61, 0xda, 0x74, 0xcc, 0x6b, 0x7, 0xbc, 0xfc, 0xa7, 0xcb, 0xbe, 0x0, 0xa6, 0x45, 0xfe, 0x4d, 0x79, 0xe2, 0xb1, 0x44, 0x2a, 0xb2, 0xd0, 0xac, 0x35, 0xa6},
			assert.NoError,
		},
		{
			"bob",
			fields{
				key:  bobSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0xde, 0x5d, 0xb3, 0x7e, 0x84, 0x8e, 0x34, 0xfc, 0x4a, 0x99, 0x99, 0x41, 0x9, 0x69, 0xed, 0xb4, 0xed, 0x20, 0x67, 0x6a, 0x72, 0x9, 0x75, 0x49, 0x68, 0xbb, 0xcf, 0x28, 0x9a, 0xc2, 0xef, 0xc2, 0x3f, 0xab, 0xad, 0x6, 0xe7, 0xfa, 0x69, 0xbb, 0xb0, 0x1f, 0x5d, 0xe0, 0xb9, 0xf6, 0xe1, 0x9d, 0x95, 0xfd, 0x1f, 0x2a, 0xb5, 0xc0, 0x36, 0x87, 0xae, 0x6c, 0x83, 0xab, 0x96, 0x5e, 0x67, 0x87},
			assert.NoError,
		},
		{
			"carlos",
			fields{
				key:  carlosSECP256R1PrivateECDSA(),
				rand: zeroReader,
			},
			args{
				message: "hello from mailchain",
			},
			[]byte{0x59, 0xcd, 0x70, 0x12, 0xdb, 0x33, 0x30, 0x4d, 0x4, 0xee, 0x9f, 0x10, 0xf0, 0x7a, 0xa3, 0x2c, 0x3d, 0xd4, 0x82, 0x26, 0x8f, 0xd9, 0xe5, 0xdc, 0xb0, 0x31, 0xec, 0xaf, 0x17, 0xaf, 0x53, 0x2c, 0x27, 0x68, 0xb4, 0x81, 0xf7, 0x46, 0x53, 0xe4, 0x25, 0xfc, 0x2a, 0xc3, 0xff, 0x73, 0xa7, 0x27, 0x82, 0xfc, 0xd, 0xc4, 0x85, 0x55, 0x78, 0x88, 0x7e, 0x18, 0x7b, 0x68, 0x2, 0x72, 0x29, 0xd1},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := PrivateKey{
				key:  tt.fields.key,
				rand: tt.fields.rand,
			}
			digest := blake2b.Sum256([]byte(tt.args.message))
			gotSignature, err := pk.Sign(digest[:])
			assert.Equal(t, tt.want, gotSignature)
			tt.assertion(t, err)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	type args struct {
		rand io.Reader
	}
	tests := []struct {
		name      string
		args      args
		want      *PrivateKey
		assertion assert.ErrorAssertionFunc
	}{
		{
			"",
			args{
				strings.NewReader("this is some data stored as a byte slice in Go Lang!"),
			},
			must.PrivateKey(PrivateKeyFromBytes([]byte{0x93, 0xd8, 0xe0, 0x84, 0x8b, 0x92, 0x84, 0xe1, 0x7f, 0xa3, 0x27, 0xab, 0x77, 0x9d,
				0x72, 0xbd, 0xb7, 0xdf, 0x42, 0xd8, 0x70, 0xb0, 0x32, 0x7b, 0x20, 0x5, 0x30, 0x23, 0x95, 0x1a, 0x36, 0x76})).(*PrivateKey),
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.args.rand)
			tt.assertion(t, err)
			assert.Equal(t, tt.want.Bytes(), got.Bytes())
		})
	}
}
