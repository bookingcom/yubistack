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
	"net/url"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/yubico"
)

type (
	// WriterFunc is a wrapper for a function to implement the Writer interface
	WriterFunc func(p []byte) (n int, err error)
	// ReaderFunc is a wrapper for a function to implement the Reader interface
	ReaderFunc func(p []byte) (n int, err error)
	// ValuesLog is mapping url.Values to a logger
	ValuesLog url.Values
	// YubikeyLog is mapping yubico.Yubikey to a logger
	YubikeyLog yubico.Yubikey
	// TokenLog is mapping yubico.Token to a logger
	TokenLog yubico.Token
	// YubikeyTSLog is mapping yubico.Yubikey timestamp to a logger
	YubikeyTSLog yubico.Yubikey
	// TokenTSLog is mapping yubico.Token timestamp to a logger
	TokenTSLog yubico.Token
)

// Write wraps a function to implement Writer interface
func (wf WriterFunc) Write(p []byte) (n int, err error) { return wf(p) }

// Read wraps a function to implement Reader interface
func (rf ReaderFunc) Read(p []byte) (n int, err error) { return rf(p) }

// MarshalZerologObject implements the zerolog interface to dump values in logger
func (vl ValuesLog) MarshalZerologObject(e *zerolog.Event) {
	values := url.Values(vl)
	for key := range values {
		e.Str(key, values.Get(key))
	}
}

// MarshalZerologObject implements the zerolog interface to dump Yubikey in logger
func (yl YubikeyLog) MarshalZerologObject(e *zerolog.Event) {
	e.Uint("ctr", yl.Counter)
	e.Uint("use", yl.Use)
}

// MarshalZerologObject implements the zerolog interface to dump Yubikey timestamp in logger
func (ytl YubikeyTSLog) MarshalZerologObject(e *zerolog.Event) {
	e.Uint("low", ytl.Low)
	e.Uint("high", ytl.High)
}

// MarshalZerologObject implements the zerolog interface to dump Token in logger
func (tl TokenLog) MarshalZerologObject(e *zerolog.Event) {
	e.Uint16("ctr", tl.Ctr)
	e.Uint8("use", tl.Use)
}

// MarshalZerologObject implements the zerolog interface to dump Token timestamp in logger
func (ttl TokenTSLog) MarshalZerologObject(e *zerolog.Event) {
	e.Uint16("low", ttl.Tstpl)
	e.Uint8("high", ttl.Tstph)
}
