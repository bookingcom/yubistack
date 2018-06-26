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
	"fmt"
	"net/url"
	"strconv"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/util"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

// https://github.com/Yubico/yubikey-val/blob/a850489d245c01c0f232db56af8ff0bfaa93fb21/ykval-config.php#L97
const (
	RelTolerance = 0.3
	AbsTolerance = 20

	SyncTimeout = 2

	SyncFast    SyncValue = 1
	SyncSecure  SyncValue = 40
	SyncDefault SyncValue = 60

	KeyClockFreq = float64(1) / float64(8)
)

var (
	// ErrInvalidTimeout is propagated when parsing of timeout fails or is invalid
	ErrInvalidTimeout = fmt.Errorf("invalid timeout string")

	// ErrInvalidSync  is propagated when parsing of sync fails or is invalid
	ErrInvalidSync = fmt.Errorf("invalid sync string")
)

type (
	// SyncValue is the synchronization percentage we need to reach to validate synchronization
	SyncValue int
	// BaseRequest structure represents the common fields of the Yubico validation protocol
	// https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html#_request
	BaseRequest struct {
		ID    uint64
		OTP   string
		Hash  string
		Nonce string
		Key   []byte
	}
	// VerifyRequest structure represents the fields of a verification request
	VerifyRequest struct {
		BaseRequest
		Timestamp bool
		Sl        SyncValue
		Timeout   int
	}
	// SyncRequest structure represents the fields of a synchronization request
	SyncRequest struct {
		BaseRequest
		Counter  uint
		Use      uint
		Low      uint
		High     uint
		Modified int64
	}
)

// Values transform a SyncRequest into a url.Values structure
func (sr SyncRequest) Values() url.Values {
	values := url.Values{
		"id":       {strconv.FormatUint(sr.ID, 10)},
		"otp":      {sr.OTP},
		"modified": {strconv.FormatInt(sr.Modified, 10)},
		"nonce":    {sr.Nonce},
		"counter":  {strconv.FormatUint(uint64(sr.Counter), 10)},
		"use":      {strconv.FormatUint(uint64(sr.Use), 10)},
		"high":     {strconv.FormatUint(uint64(sr.High), 10)},
		"low":      {strconv.FormatUint(uint64(sr.Low), 10)},
	}

	values.Set("hash", util.SignEncodeBase64([]byte(values.Encode()), sr.Key))
	return values
}

// Token creates a token out of a SyncRequest
func (sr SyncRequest) Token() *yubico.Token {
	return &yubico.Token{
		Token: &yubikey.Token{
			Ctr: uint16(sr.Counter), Use: uint8(sr.Use),
			Tstph: uint8(sr.High), Tstpl: uint16(sr.Low),
		},
	}
}

// String dump a SyncRequest into a readable string
func (sr SyncRequest) String() string {
	return fmt.Sprintf("id: %d, token: {%s}", sr.ID, sr.Token())
}

// String dump a VerifyRequest into a readable string
func (vr VerifyRequest) String() string {
	return fmt.Sprintf("id: %d, timestamp: %t, sync: %d, timeout: %d",
		vr.ID, vr.Timestamp, vr.Sl, vr.Timeout)
}

// ParseTimeoutString parse timeout as a string to an int
func ParseTimeoutString(timeout string) (int, error) {
	// if timeout not set we return the default value
	if timeout == "" {
		return SyncTimeout, nil
	}
	duration, err := strconv.Atoi(timeout)
	if err != nil || duration < 1 {
		return 0, ErrInvalidTimeout
	}
	return duration, nil
}

// ParseBaseRequest parse a url.Values structure and return a BaseRequest object
func ParseBaseRequest(logger zerolog.Logger, loader yubico.ClientLoader, values url.Values) (req BaseRequest, err error) {
	req.Nonce, req.OTP = values.Get("nonce"), values.Get("otp")
	req.Hash = values.Get("hash")
	values.Del("hash")

	if req.ID, err = ValidateID(values.Get("id")); err != nil {
		logger.Error().Err(err).Str("client", values.Get("id")).Msg("failed to validate client id")
		return
	}
	if err = ykksm.ValidateOTP(values.Get("otp")); err != nil {
		logger.Error().Err(err).Str("otp", values.Get("otp")).Msg("failed to validate otp")
		return
	}
	if err = ValidateNonce(values.Get("nonce")); err != nil {
		logger.Error().Err(err).Str("nonce", values.Get("nonce")).Msg("failed to validate nonce")
		return
	}
	if client, err := loader.LoadClient(req.ID); err == nil {
		req.Key = client.Key()
	} else {
		logger.Error().Err(err).Uint64("client", req.ID).Msg("failed to load client")
		return req, err
	}
	if err = ValidateSignature(req.Hash, values.Encode(), req.Key); err != nil {
		logger.Error().Err(err).Str("hash", req.Hash).Msg("failed to validate signature")
		return
	}

	return
}

// ParseSyncRequest parse url.Values structure and return a SyncRequest object
func ParseSyncRequest(logger zerolog.Logger, loader yubico.ClientLoader, values url.Values) (req SyncRequest, err error) {
	logger.Debug().Object("query", util.ValuesLog(values)).Msg("parsing request")
	log := func(k, v string, err error) {
		logger.Error().Err(err).Str(k, v).Msg("failed to parse field")
	}
	parseUint := func(s string) (uint, error) {
		v, err := strconv.ParseUint(s, 10, 64)
		return uint(v), err
	}
	if req.BaseRequest, err = ParseBaseRequest(logger, loader, values); err != nil {
		return
	}

	if req.Counter, err = parseUint(values.Get("counter")); err != nil {
		log("counter", values.Get("counter"), err)
		return req, ErrMissingParameter
	}
	if req.Use, err = parseUint(values.Get("use")); err != nil {
		log("use", values.Get("use"), err)
		return req, ErrMissingParameter
	}
	if req.Low, err = parseUint(values.Get("low")); err != nil {
		log("low", values.Get("low"), err)
		return req, ErrMissingParameter
	}
	if req.High, err = parseUint(values.Get("high")); err != nil {
		log("high", values.Get("high"), err)
		return req, ErrMissingParameter
	}
	req.Modified, err = strconv.ParseInt(values.Get("modified"), 10, 64)
	if err != nil {
		log("modified", values.Get("modified"), err)
		return req, ErrMissingParameter
	}
	// nolint:nakedret
	return
}

// ParseSyncString parses synch string to an int
func ParseSyncString(sync string) (SyncValue, error) {
	switch sync {
	case "": // value unset we return default
		return SyncDefault, nil
	case "fast":
		return SyncFast, nil
	case "secure":
		return SyncSecure, nil
	default:
		duration, err := strconv.Atoi(sync)
		if err != nil || duration <= 0 || duration > 100 {
			return 0, ErrInvalidSync
		}
		return SyncValue(duration), nil
	}
}

// ParseVerifyRequest parse url.Values structure and return a VerifyRequest object
func ParseVerifyRequest(logger zerolog.Logger, loader yubico.ClientLoader, values url.Values) (req VerifyRequest, err error) {
	logger.Debug().Object("query", util.ValuesLog(values)).Msg("parsing request")
	if req.BaseRequest, err = ParseBaseRequest(logger, loader, values); err != nil {
		return
	}
	req.Timestamp = values.Get("timestamp") == "1"
	if req.Timeout, err = ParseTimeoutString(values.Get("timeout")); err != nil {
		return
	}
	if req.Sl, err = ParseSyncString(values.Get("sl")); err != nil {
		return
	}
	return
}
