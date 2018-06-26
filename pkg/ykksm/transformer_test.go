// Copyright 2020 Booking.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

package ykksm

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/bookingcom/yubistack/internal"
)

func genKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

//nolint:golint,gochecknoglobals
var entriesRetrieveTransformer = []struct {
	retriever    Retriever
	transformers []Transformer
	key          []byte
	err          error
}{
	{
		RetrieverFunc(func([]byte) ([]byte, string, error) {
			// printf "foo" |  hexdump -v -e '1/1 "%02x"'
			return []byte("666f6f"), "", nil
		}),
		[]Transformer{HexTransformer}, []byte("foo"), nil,
	},
	{
		RetrieverFunc(func([]byte) ([]byte, string, error) {
			// printf "foo" |  base64
			return []byte("Zm9v"), "", nil
		}),
		[]Transformer{Base64Transformer}, []byte("foo"), nil,
	},
	{
		RetrieverFunc(func([]byte) ([]byte, string, error) {
			// printf "foo" | hexdump -v -e '1/1 "%02x"' |  base64
			return []byte("NjY2ZjZm"), "", nil
		}),
		[]Transformer{Base64Transformer, HexTransformer}, []byte("foo"), nil,
	},
	{
		RetrieverFunc(func([]byte) ([]byte, string, error) {
			return []byte("foo"), "", nil
		}),
		[]Transformer{OAEPTransformer(genKey()), Base64Transformer, HexTransformer},
		nil, fmt.Errorf("crypto/rsa: decryption error"),
	},
	{
		RetrieverFunc(func([]byte) ([]byte, string, error) {
			return nil, "", internal.ErrNoop
		}),
		[]Transformer{}, nil, internal.ErrNoop,
	},
}

func TestRetrieveTransformer(t *testing.T) {
	for i, entry := range entriesRetrieveTransformer {
		retriever := RetrieveTransformer(entry.retriever, entry.transformers...)
		key, _, err := retriever.Retrieve(nil)
		if string(key) != string(entry.key) || !internal.ErrEqual(err, entry.err) {
			t.Errorf("Retrieve(%d) want: %q, %s - got: %q, %s",
				i, entry.key, internal.TestError(entry.err),
				key, internal.TestError(err))
		}
	}
}
