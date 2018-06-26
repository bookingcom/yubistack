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
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/yubico"
)

var (
	// ErrNoOTP is an error returned when no OTP is provided
	ErrNoOTP = errors.New("no OTP provided")
	// ErrInvalidOTP is an error returned when OTP is wrong format
	ErrInvalidOTP = errors.New("invalid OTP format")
	// ErrCorruptOTP is an error returned when OTP is corrupted
	ErrCorruptOTP = errors.New("corrupt OTP")
	// ErrNoYubikey is an error returned when no Yubikey can be found
	ErrNoYubikey = errors.New("no YubiKey found")
)

type (
	// DecrypterFactory is currying a Decrypter to inject a logger on each request
	DecrypterFactory func(zerolog.Logger) Decrypter
	// DecrypterFunc is a wrapper for a function to implement the Decrypter interface
	DecrypterFunc func(otp string) (*yubico.Token, error)
	// Decrypter interface abstract the decryption of a token into a Token struct
	Decrypter interface {
		Decrypt(otp string) (*yubico.Token, error)
	}
	// Retriever interface abstract the retrieval of a key from a store
	Retriever interface {
		Retrieve(pubid []byte) (key []byte, name string, err error)
	}
	// RetrieverFunc is a wrapper for a function to implement the Retriever interface
	RetrieverFunc func(pubid []byte) (key []byte, name string, err error)
	// YKKSM struct handles the features of the yubico KSM module
	YKKSM struct {
		Retriever
		zerolog.Logger
	}
)

// Decrypt wraps a function to implement Decrypter interface
func (df DecrypterFunc) Decrypt(otp string) (*yubico.Token, error) { return df(otp) }

// Retrieve wraps a function to implement the Retrieve interface
func (rf RetrieverFunc) Retrieve(pubid []byte) ([]byte, string, error) { return rf(pubid) }

// NewKSM creates a new instance of a YKKSM with sensible defaults
func NewKSM(retriever Retriever, options ...func(*YKKSM)) *YKKSM {
	ykksm := &YKKSM{Retriever: retriever, Logger: zerolog.Nop()}
	for _, option := range options {
		option(ykksm)
	}
	return ykksm
}

// ValidateOTP check if the provided string is a proper yubikey token
func ValidateOTP(otp string) error {
	if otp == "" {
		return ErrNoOTP
	}

	if len(otp) < 32 || len(otp) > 48 || !yubikey.ModHexP([]byte(otp)) {
		return ErrInvalidOTP
	}
	return nil
}

// Decrypt implements the Decrypter interface and perform an otp decryption.
func (ykksm YKKSM) Decrypt(otp string) (*yubico.Token, error) {
	if err := ValidateOTP(otp); err != nil {
		ykksm.Error().Err(err).Msgf("otp: %s", otp)
		return nil, err
	}
	pubid, yotp, _ := yubikey.ParseOTPString(otp)
	aes, name, err := ykksm.Retrieve(pubid)
	if err != nil {
		ykksm.Error().Err(err).Msgf("failed to retrieve %s", pubid)
		return nil, err
	}
	key := yubikey.Key{}
	copy(key[:], aes)
	token, err := yotp.Parse(key)
	if err != nil {
		ykksm.Error().Err(err).Msgf("failed to parse key: %s", ErrCorruptOTP)
		return nil, ErrCorruptOTP
	}

	nameBytes, err := hex.DecodeString(name)
	if err != nil {
		ykksm.Error().Err(err).Msgf("failed to decode name")
		return nil, err
	}

	if !bytes.Equal(nameBytes, token.Uid[:]) {
		ykksm.Error().Err(ErrCorruptOTP).Msgf("UID mismatch")
		return nil, ErrCorruptOTP
	}
	return &yubico.Token{Token: token, Public: string(pubid)}, nil
}
