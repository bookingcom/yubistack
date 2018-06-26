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
	"fmt"
	"testing"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

//nolint:golint,gochecknoglobals
var aes = []byte{'\xec', '\xde', '\x18', '\xdb', '\xe7', '\x6f', '\xbd', '\x0c',
	'\x33', '\x33', '\x0f', '\x1c', '\x35', '\x48', '\x71', '\xdb'}

//nolint:golint,gochecknoglobals
var testValidateOTPEntries = []struct {
	otp string
	err error
}{
	{"", ErrNoOTP},
	{"jbrjnlnldnhcujvddbikngjrtgh", ErrInvalidOTP},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgha", ErrInvalidOTP},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtghhhhhhhhhh", ErrInvalidOTP},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtghhhhhhhhh", nil},
}

func TestValidateOTP(t *testing.T) {
	for _, entry := range testValidateOTPEntries {
		if err := ValidateOTP(entry.otp); err != entry.err {
			t.Errorf("ValidateOTP(%q) => got: %q, want: %q", entry.otp, err, entry.err)
		}
	}
}

func retriever(key []byte, name string, err error) Retriever {
	return RetrieverFunc(func([]byte) ([]byte, string, error) { return key, name, err })
}

//nolint:golint,gochecknoglobals
var testDecryptEntries = []struct {
	otp       string
	token     *yubico.Token
	err       error
	retriever Retriever
}{
	{"", nil, ErrNoOTP, nil},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", nil, internal.ErrNoop,
		retriever(nil, "", internal.ErrNoop)},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", nil, ErrCorruptOTP,
		retriever([]byte{'a'}, "", nil)},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", nil,
		fmt.Errorf("encoding/hex: invalid byte: U+006F 'o'"),
		retriever(aes, "foo", nil)},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", nil,
		ErrCorruptOTP,
		retriever(aes, "9792ebfe26cc", nil)},
	{"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh",
		internal.TokenAll("dteffuje", 19, 17, 0, 49712),
		nil, retriever(aes, "8792ebfe26cc", nil)},
}

func TestKSMDecrypt(t *testing.T) {
	ksm := NewKSM(nil, func(ksm *YKKSM) { ksm.Logger = zerolog.Nop() })
	for _, entry := range testDecryptEntries {
		ksm.Retriever = entry.retriever
		token, err := ksm.Decrypt(entry.otp)
		if !internal.ErrEqual(entry.err, err) || !internal.TokenEqual(entry.token, token) {
			t.Errorf("YKKSM.Decrypt(%q) => got: %s, %q, want %s, %q",
				entry.otp, internal.TestToken(token), err,
				internal.TestToken(entry.token), entry.err)
		}
	}
}
