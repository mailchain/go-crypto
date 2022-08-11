package noop

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/mailchain/mailchain/crypto/cipher"
)

func TestNewDecrypter(t *testing.T) {
	tests := []struct {
		name string
		want Decrypter
	}{
		{
			"success",
			Decrypter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDecrypter(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDecrypter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	type args struct {
		data cipher.EncryptedContent
	}
	tests := []struct {
		name    string
		d       Decrypter
		args    args
		want    cipher.PlainContent
		err     error
		wantErr bool
	}{
		{
			"success",
			NewDecrypter(),
			args{
				bytesEncode(cipher.EncryptedContent([]byte("test content"))),
			},
			cipher.PlainContent([]byte("test content")),
			nil,
			false,
		},
		{
			"err-invalid-prefix",
			NewDecrypter(),
			args{
				cipher.EncryptedContent([]byte("test content")),
			},
			nil,
			fmt.Errorf("invalid prefix"),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Decrypter{}
			got, err := d.Decrypt(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypter.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err != nil && err.Error() != tt.err.Error() {
				t.Errorf("Decrypter.Decrypt() error = %v, want %v", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypter.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
