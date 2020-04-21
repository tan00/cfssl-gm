// Package derhelpers implements common functionality
// on DER encoded data
package derhelpers

import (
	"crypto"
	"testing"

	"github.com/cloudflare/cfssl/gmsm/sm2"
)

func TestParsePrivateKeyDER(t *testing.T) {
	type args struct {
		keyDER []byte
	}

	type testcase struct {
		name    string
		args    args
		wantKey crypto.Signer
		wantErr bool
	}

	priv, _ := sm2.GenerateKey()
	derbyte, _ := sm2.MarshalSm2PrivateKey(priv, nil)

	var tests []testcase
	tests = append(tests, testcase{"case1", args{keyDER: derbyte}, nil, false})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKeyDER(tt.args.keyDER)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeyDER() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if !reflect.DeepEqual(gotKey, tt.wantKey) {
			// 	t.Errorf("ParsePrivateKeyDER() = %v, want %v", gotKey, tt.wantKey)
			// }
		})
	}
}
