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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/yubico"
)

const (
	// SyncResp is the format of the standard synchronize response from a YKVal module
	SyncResp = "OK counter=%d use=%d high=%d low=%d"
)

type (
	// HTTPDoerFunc is a wrapper for a function to implement the HttpDoer interface
	HTTPDoerFunc func(*http.Request) (*http.Response, error)
	// HTTPDoer is an interface abstracting the Do function allowing us to plug
	// alternative flows
	HTTPDoer interface {
		Do(*http.Request) (*http.Response, error)
	}
	// SyncClient is responsible to handle sync request lifecycle
	SyncClient struct {
		zerolog.Logger
		HTTPDoer
		SyncRequest
		context context.Context
		cancel  context.CancelFunc
	}
)

// Do wraps a function to implement HTTPDoer interface
func (df HTTPDoerFunc) Do(req *http.Request) (*http.Response, error) { return df(req) }

// CreateSync creates a new SyncRequest with proper fields setup
func CreateSync(req VerifyRequest, ykey *yubico.Yubikey) SyncRequest {
	return SyncRequest{BaseRequest: req.BaseRequest, Counter: ykey.Counter,
		Use: ykey.Use, Low: ykey.Low, High: ykey.High, Modified: time.Now().Unix()}
}

// SyncClientTimeoutOpt setter for private fields used at initialization
func SyncClientTimeoutOpt(timeout int) func(*SyncClient) {
	return func(sc *SyncClient) {
		sc.context, sc.cancel = context.WithTimeout(
			context.Background(), time.Duration(timeout)*time.Second,
		)
	}
}

// NewSyncClient creates a new instance of the SyncClient structure
// by passing options you can set up some internal fields
func NewSyncClient(options ...func(*SyncClient)) *SyncClient {
	sc := &SyncClient{Logger: zerolog.Nop(), HTTPDoer: http.DefaultClient}
	for _, option := range options {
		option(sc)
	}
	if sc.context == nil {
		SyncClientTimeoutOpt(SyncTimeout)(sc)
	}
	return sc
}

// Context is a getter of the internal context.Context
func (sc *SyncClient) Context() context.Context { return sc.context }

// Cancel propagate the cancellation to the internal http.Client
func (sc *SyncClient) Cancel() { sc.cancel() }

// Send is sending the internal SyncRequest, parse the response and return nil
// if something bad happen
func (sc *SyncClient) Send(uri string) *yubico.Yubikey {
	var status string
	var counter, use, high, low uint
	var logger = sc.With().Str("uri", uri).Logger()

	req, err := http.NewRequest(http.MethodGet, uri+"?"+sc.Values().Encode(), nil)
	if err != nil {
		logger.Err(err).Msg("failed to create sync request")
		return nil
	}
	resp, err := sc.Do(req.WithContext(sc.context))
	switch e := err.(type) {
	case *url.Error:
		// if error is type url.Error, unwrap and if context is canceled do not log
		if e.Err != context.Canceled {
			logger.Err(err).Msg("failed to send sync request")
		}
		return nil
	case error:
		logger.Err(err).Msg("failed to send sync request")
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Err(err).Msg("failed to read sync response")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		if _, err := fmt.Sscanf(string(body), "ERR %s", &status); err != nil {
			logger.Err(err).Msgf("failed parsing syncing response: %s", body)
		} else {
			logger.Error().Msgf("failed syncing: %s", NewStatus(status))
		}
		return nil
	}
	if _, err := fmt.Sscanf(string(body), SyncResp, &counter, &use, &high, &low); err != nil {
		logger.Err(err).Msgf("failed parsing syncing response: %s", body)
		return nil
	}
	return &yubico.Yubikey{Counter: counter, Use: use, High: high, Low: low}
}
