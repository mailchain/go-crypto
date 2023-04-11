package secp256r1_test

import (
	"testing"

	"github.com/mailchain/go-crypto"

	"github.com/mailchain/go-crypto/secp256r1/secp256r1test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestSignVerify(t *testing.T) {
	type args struct {
		signingKey   crypto.PrivateKey
		verifyingKey crypto.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      bool
		assertion assert.ErrorAssertionFunc
	}{
		{
			"alice",
			args{
				secp256r1test.AlicePrivateKey,
				secp256r1test.AlicePublicKey,
			},
			true,
			assert.NoError,
		},
		{
			"bob",
			args{
				secp256r1test.BobPrivateKey,
				secp256r1test.BobPublicKey,
			},
			true,
			assert.NoError,
		},
		{
			"carlos",
			args{
				secp256r1test.CarlosPrivateKey,
				secp256r1test.CarlosPublicKey,
			},
			true,
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := blake2b.Sum256([]byte("test message"))
			signature, err := tt.args.signingKey.Sign(digest[:])
			tt.assertion(t, err)

			verified := tt.args.verifyingKey.Verify(digest[:], signature)
			assert.Equal(t, tt.want, verified)
		})
	}
}
