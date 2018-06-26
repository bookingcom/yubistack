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

package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
)

var (
	// ErrPEMDecode is used to be propagated up the call stack.
	// It is returned when something goes wrong in the crypt module.
	ErrPEMDecode = fmt.Errorf("failed to decode PEM block containing private key")

	reader = rand.Reader //nolint:golint,gochecknoglobals
	empty  = []byte("")  //nolint:golint,gochecknoglobals
)

// DecodeRSAOAEP decode a cipher using the rsa private key argument.
// It uses the rsa.DecryptOAEP function under the hood
func DecodeRSAOAEP(key *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	cipher, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, cipher, empty)
	return cipher, err
}

// DecodeRSAKey decode a slice of bytes into an rsa.PrivateKey.
// It uses the x509.ParsePKCS1PrivateKey function under the hood
func DecodeRSAKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrPEMDecode
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ReadRSAKeyFromFile read a file and decode the content into a rsa.PrivateKey
func ReadRSAKeyFromFile(path string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return DecodeRSAKey(bytes)
}

// Sign is using HMAC and sha256 to create a signature of a cipher
func Sign(cipher, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(cipher)
	return h.Sum(nil)
}

// SignEncodeBase64 sign a cipher and return the base64 signature
func SignEncodeBase64(cipher, key []byte) string {
	sign := Sign(cipher, key)
	return base64.StdEncoding.EncodeToString(sign)
}

// IsSignValid checks if the signature of a given cipher is valid with the given key
func IsSignValid(hash, cipher string, key []byte) bool {
	sign, err := base64.StdEncoding.DecodeString(hash)
	return err == nil && len(sign) == sha256.Size &&
		hmac.Equal(sign, Sign([]byte(cipher), key))
}

// Nonce function creates a random base62 string of size n
func Nonce(n int) (string, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(reader, b)
	str := base64.StdEncoding.EncodeToString(b)
	str = strings.ReplaceAll(str, "+", "3")
	str = strings.ReplaceAll(str, "/", "7")
	str = strings.ReplaceAll(str, "=", "1")
	return str, err
}
