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

package ykval

import (
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/yubico"
)

type (
	// VerifierFactory is currying a Verifier to inject a logger on each request
	VerifierFactory func(zerolog.Logger) Verifier
	// VerifierFunc is a wrapper for a function to implement the Verifier interface
	VerifierFunc func(VerifyRequest) (*yubico.Yubikey, error)
	// Verifier interface abstracts the verification of the token over network clients
	Verifier interface {
		Verify(VerifyRequest) (*yubico.Yubikey, error)
	}
)

// Verify wraps a function to implement Verify interface
func (vf VerifierFunc) Verify(r VerifyRequest) (*yubico.Yubikey, error) { return vf(r) }

type (
	// SynchronizerFactory is currying a Synchronizer to inject a logger on each request
	SynchronizerFactory func(zerolog.Logger) Synchronizer
	// SynchronizerFunc is a wrapper for a function to implement the Synchronizer interface
	SynchronizerFunc func(SyncRequest) (*yubico.Yubikey, error)
	// Synchronizer interface abstract the handling of a synchronize request
	Synchronizer interface {
		Synchronize(request SyncRequest) (*yubico.Yubikey, error)
	}
)

// Synchronize wraps a function to implement Synchronizer interface
func (sf SynchronizerFunc) Synchronize(r SyncRequest) (*yubico.Yubikey, error) { return sf(r) }

// YubikeyDBMapperFactory is currying a YubikeyDBMapper to inject a logger on each request
type YubikeyDBMapperFactory func(zerolog.Logger) yubico.YubikeyDBMapper
