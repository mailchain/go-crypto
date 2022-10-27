package aes256cbc

import (
	"testing"

	"github.com/mailchain/go-encoding/encodingtest"
)

func Test_encryptedData_verify(t *testing.T) {
	type fields struct {
		InitializationVector      []byte
		EphemeralPublicKey        []byte
		Ciphertext                []byte
		MessageAuthenticationCode []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			"success",
			fields{
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d16"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292f4dc68f918446332837aa57cd5145235cc40702d962cbb53ac27fb2246fb6cbadc"),
				encodingtest.MustDecodeHex("2c8432ca"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292"),
			},
			false,
		},
		{
			"err-iv",
			fields{
				encodingtest.MustDecodeHex(""),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292f4dc68f918446332837aa57cd5145235cc40702d962cbb53ac27fb2246fb6cbadc"),
				encodingtest.MustDecodeHex("2c8432ca"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292"),
			},
			true,
		},
		{
			"err-ethemeral-pk",
			fields{
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d16"),
				encodingtest.MustDecodeHex(""),
				encodingtest.MustDecodeHex("2c8432ca"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292"),
			},
			true,
		},
		{
			"err-cipher-text",
			fields{
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d16"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292f4dc68f918446332837aa57cd5145235cc40702d962cbb53ac27fb2246fb6cbadc"),
				encodingtest.MustDecodeHex(""),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292"),
			},
			true,
		},
		{
			"err-mac",
			fields{
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d16"),
				encodingtest.MustDecodeHex("2c8432ca28ce929b86a47f2d40413d161f591f8985229060491573d83f82f292f4dc68f918446332837aa57cd5145235cc40702d962cbb53ac27fb2246fb6cbadc"),
				encodingtest.MustDecodeHex("2c8432ca"),
				encodingtest.MustDecodeHex(""),
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &encryptedData{
				InitializationVector:      tt.fields.InitializationVector,
				EphemeralPublicKey:        tt.fields.EphemeralPublicKey,
				Ciphertext:                tt.fields.Ciphertext,
				MessageAuthenticationCode: tt.fields.MessageAuthenticationCode,
			}
			if err := e.verify(); (err != nil) != tt.wantErr {
				t.Errorf("encryptedData.verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
