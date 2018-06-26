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

package ykauth

import (
	"fmt"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"
	crypt "github.com/tredoe/osutil/user/crypt/sha256_crypt"

	"github.com/bookingcom/yubistack/pkg/util"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

const (
	// NonceSize is the fixed value of the nonce used during exchange of requests
	NonceSize = 20
)

//nolint:golint,gochecknoglobals
var (
	// ErrInvalidPassword is the error returned up the stack when password is invalid
	ErrInvalidPassword = fmt.Errorf("invalid password")
	// ErrNoUser is the error returned up the stack when no user is found
	ErrNoUser = fmt.Errorf("no matching user")

	// only support sha256 hashed passwords for now
	crypter = crypt.New()
)

type (
	// YKAuth is the base structure responsible for handling YKAuth flow
	YKAuth struct {
		zerolog.Logger
		ykval.Verifier
		yubico.UserLoader
		*yubico.Client
		NonceFunc func(int) (string, error)
		timeout   int
		sync      ykval.SyncValue
	}
)

// NewYKAuth creates a new YKAuth instance
func NewYKAuth(client *yubico.Client, options ...func(*YKAuth)) *YKAuth {
	y := &YKAuth{
		Logger: zerolog.Nop(),
		Verifier: ykval.VerifierFunc(func(ykval.VerifyRequest) (*yubico.Yubikey, error) {
			return nil, fmt.Errorf("dumb verifier")
		}),
		UserLoader: yubico.UserLoaderFunc(func(string, string) (*yubico.User, error) {
			return nil, fmt.Errorf("dumb loader")
		}),
		Client: client, NonceFunc: util.Nonce,
	}
	for _, option := range options {
		option(y)
	}
	if y.timeout <= 0 {
		y.timeout = ykval.SyncTimeout
	}
	if y.sync <= 0 || y.sync > 100 {
		y.sync = ykval.SyncDefault
	}
	return y
}

// Authenticate tries to authenticate a user with password + otp
func (y *YKAuth) Authenticate(name, password, otp string) error {
	logger := y.With().Str("name", name).Logger()
	logger.Debug().Msg("authenticating")
	pub, _, err := yubikey.ParseOTPString(otp)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse OTP")
		return err
	}
	user, err := y.LoadUser(name, string(pub))
	if err != nil {
		logger.Error().Err(err).Msg("failed to load user")
		return err
	}
	if !VerifyPassword(password, user.Hash) {
		logger.Error().Msg("failed to verify password")
		return ErrInvalidPassword
	}
	return nil
}

// Authorize tries to authorize a user given its name and otp
func (y *YKAuth) Authorize(name, otp string) error {
	logger := y.With().Str("name", name).Logger()
	pub, _, err := yubikey.ParseOTPString(otp)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse OTP")
		return err
	}
	if _, err = y.LoadUser(name, string(pub)); err != nil {
		logger.Error().Err(err).Msg("failed to load user")
		return err
	}
	nonce, err := y.NonceFunc(NonceSize)
	if err != nil {
		logger.Error().Err(err).Msg("failed to generate nonce")
		return err
	}
	verify := ykval.VerifyRequest{
		BaseRequest: ykval.BaseRequest{ID: uint64(y.ID), OTP: otp, Key: y.Key(), Nonce: nonce},
		Timeout:     y.timeout,
		Sl:          y.sync,
	}
	if _, err := y.Verify(verify); err != nil {
		logger.Error().Err(err).Msg("failed to verify token")
		return err
	}
	return nil
}

// TimeoutOpt set the internal timeout
func TimeoutOpt(timeout int) func(*YKAuth) {
	return func(auth *YKAuth) { auth.timeout = timeout }
}

// SyncOpt set the internal sync level
func SyncOpt(sync ykval.SyncValue) func(auth *YKAuth) {
	return func(auth *YKAuth) { auth.sync = sync }
}
