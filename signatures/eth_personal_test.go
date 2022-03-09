package signatures

import (
	"testing"

	"github.com/mailchain/mailchain/crypto"
	"github.com/mailchain/mailchain/crypto/ed25519/ed25519test"
	"github.com/mailchain/mailchain/crypto/secp256k1/secp256k1test"
	"github.com/mailchain/mailchain/encoding/encodingtest"
	"github.com/stretchr/testify/assert"
)

func TestSignEthereumPersonalMessage(t *testing.T) {
	type args struct {
		key     crypto.PrivateKey
		message []byte
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"secp256k1-alice",
			args{
				secp256k1test.AlicePrivateKey,
				[]byte("hello"),
			},
			encodingtest.MustDecodeHex("1a8cb54a9fd44f18e0799b081fb725b54409e46f9d6ddb2c2e720de1c60c66030a9038c28a2d0c5a68def8fcb5359ca7bceb5afe943424d610fa91cda27cf1221c"),
			assert.NoError,
		},
		{
			"secp256k1-bob",
			args{
				secp256k1test.BobPrivateKey,
				[]byte("hello"),
			},
			encodingtest.MustDecodeHex("cbf4e3962fd6e9c711cb622bceb4205649437792c395a772fe452e802964a91a6734bbd6cbad4a42fa57fe2f2a664ef627152a0cf257f0341b0f960c224422881b"),
			assert.NoError,
		},
		{
			"ed25519-alice",
			args{
				ed25519test.AlicePrivateKey,
				[]byte("hello"),
			},
			nil,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignEthereumPersonalMessage(tt.args.key, tt.args.message)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
