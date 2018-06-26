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
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"

	"github.com/bookingcom/yubistack/pkg/util"
)

type (
	// TransformerFunc is a wrapper for a function to implement the Tranformer interface
	TransformerFunc func([]byte) ([]byte, error)
	// Transformer is an interface abstracting the transformations made on a byte slice.
	Transformer interface {
		Transform(key []byte) ([]byte, error)
	}
)

// Transform wraps a function to implement Transformer interface
func (tf TransformerFunc) Transform(key []byte) ([]byte, error) { return tf(key) }

// HexTransformer decodes a slice of hexadecimal bytes to a slice of bytes
//nolint:golint,gochecknoglobals
var HexTransformer = TransformerFunc(func(key []byte) ([]byte, error) {
	n, err := hex.Decode(key, key)
	return key[:n], err
})

// Base64Transformer decodes a slice of base64 bytes to a slice of bytes
//nolint:golint,gochecknoglobals
var Base64Transformer = TransformerFunc(func(key []byte) ([]byte, error) {
	n, err := base64.StdEncoding.Decode(key, key)
	return key[:n], err
})

// OAEPTransformer return a Transformer which decode a slice of byte using a RSA key.
func OAEPTransformer(private *rsa.PrivateKey) Transformer {
	return TransformerFunc(func(key []byte) ([]byte, error) {
		return util.DecodeRSAOAEP(private, key)
	})
}

// RetrieveTransformer pipes a retrieved key to a list of tranformers and return the result
func RetrieveTransformer(retriever Retriever, transformers ...Transformer) Retriever {
	return RetrieverFunc(func(pubid []byte) (key []byte, name string, err error) {
		if key, name, err = retriever.Retrieve(pubid); err != nil {
			return
		}
		for _, transformer := range transformers {
			if key, err = transformer.Transform(key); err != nil {
				return
			}
		}
		return
	})
}
