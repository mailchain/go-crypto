package nacl

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/mailchain/go-crypto"
	"github.com/mailchain/go-crypto/cipher"
	"github.com/mailchain/go-crypto/cipher/ecdh"
	"github.com/mailchain/go-crypto/ed25519/ed25519test"
	"github.com/mailchain/go-crypto/secp256k1/secp256k1test"
	"github.com/mailchain/go-crypto/sr25519/sr25519test"
	"github.com/mailchain/go-encoding/encodingtest"
	"github.com/stretchr/testify/assert"
)

func TestNewPrivateKeyEncrypter(t *testing.T) {
	type args struct {
		privateKey crypto.PrivateKey
	}
	tests := []struct {
		name      string
		args      args
		want      *PrivateKeyEncrypter
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1",
			args{
				secp256k1test.AlicePrivateKey,
			},
			&PrivateKeyEncrypter{
				rand:       rand.Reader,
				privateKey: secp256k1test.AlicePrivateKey,
				keyExchange: func() cipher.KeyExchange {
					k, _ := ecdh.NewSECP256K1(rand.Reader)
					return k
				}(),
			},
			assert.NoError,
		},
		{
			"ed25519",
			args{
				ed25519test.AlicePrivateKey,
			},
			&PrivateKeyEncrypter{
				rand:       rand.Reader,
				privateKey: ed25519test.AlicePrivateKey,
				keyExchange: func() cipher.KeyExchange {
					k, _ := ecdh.NewED25519(rand.Reader)
					return k
				}(),
			},
			assert.NoError,
		},
		{
			"sr25519",
			args{
				sr25519test.AlicePrivateKey,
			},
			&PrivateKeyEncrypter{
				rand:       rand.Reader,
				privateKey: sr25519test.AlicePrivateKey,
				keyExchange: func() cipher.KeyExchange {
					k, _ := ecdh.NewSR25519(rand.Reader)
					return k
				}(),
			},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPrivateKeyEncrypter(tt.args.privateKey)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrivateKeyEncrypter_Encrypt(t *testing.T) {
	type fields struct {
		rand        io.Reader
		privateKey  crypto.PrivateKey
		keyExchange cipher.KeyExchange
	}
	type args struct {
		message cipher.PlainContent
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      cipher.EncryptedContent
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1-alice",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				secp256k1test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSECP256K1(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			encodingtest.MustDecodeHex("2be14142434445464748494a4b4c4d4e4f5051525354555657585ff8026ea550c27f5ec06e3ecdfb0850f3352400b7e9e2"),
			assert.NoError,
		},
		{
			"secp256k1-bob",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				secp256k1test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSECP256K1(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			encodingtest.MustDecodeHex("2be14142434445464748494a4b4c4d4e4f5051525354555657583abb4c6b03073d8318a8edfa5e3820d761b9d07682e179"),
			assert.NoError,
		},
		{
			"ed25519-alice",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				ed25519test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewED25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f505152535455565758ede31931c34d9e1d251cf6466b1d628957a55bcce73486"),
			assert.NoError,
		},
		{
			"ed25519-bob",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				ed25519test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewED25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			encodingtest.MustDecodeHex("2be24142434445464748494a4b4c4d4e4f5051525354555657581a7d53c9fc1d9b4103f7e9c234f5897688cc68dbadbe17"),
			assert.NoError,
		},
		{
			"sr25519-alice",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				sr25519test.AlicePrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSR25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			nil,
			assert.Error,
		},
		{
			"sr25519-bob",
			fields{
				bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
				sr25519test.BobPrivateKey,
				func() cipher.KeyExchange {
					k, _ := ecdh.NewSR25519(bytes.NewReader([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ")))
					return k
				}(),
			},
			args{
				[]byte("message"),
			},
			nil,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := PrivateKeyEncrypter{
				rand:        tt.fields.rand,
				privateKey:  tt.fields.privateKey,
				keyExchange: tt.fields.keyExchange,
			}
			got, err := e.Encrypt(tt.args.message)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
