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

package http

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"
)

const (
	endpoint = "http://localhost:8081/wsapi/decrypt"
)

var (

	// ErrBadKSMResponse is simple error to propagate up the call stack
	ErrBadKSMResponse = errors.New("bad response from KSM")
)

// KSMClient is validating token over the network to a specific endpoint
type KSMClient struct {
	Endpoint string
	Logger   zerolog.Logger
}

// NewClient creates a new instance with sensible defaults
func NewClient(options ...func(*KSMClient)) *KSMClient {
	client := &KSMClient{endpoint, zerolog.Nop()}
	for _, option := range options {
		option(client)
	}
	return client
}

// Decrypt delegate the decryption of an otp token to a remote endpoint over HTTP
func (k *KSMClient) Decrypt(otp string) (*yubikey.Token, error) {
	u := url.Values{
		"otp": {otp},
	}

	resp, err := http.PostForm(k.Endpoint, u)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, ErrBadKSMResponse
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) < 3 {
		return nil, ErrBadKSMResponse
	}

	if bytes.HasPrefix(body, []byte("ERR")) {
		// check we're not overflowing our slice
		return nil, errors.New(string(body[4:]))
	}

	if bytes.HasPrefix(body, []byte("OK ")) {
		// success!
		token := &yubikey.Token{}

		count, err := fmt.Sscanf(
			string(body), "OK counter=%04x low=%04x high=%02x use=%02x",
			&token.Ctr, &token.Tstpl, &token.Tstph, &token.Use,
		)

		if count != 4 || err != nil {
			k.Logger.Err(err).Int("count", count).
				Msg("failed to scan http response")
			err = ErrBadKSMResponse
		}

		return token, err
	}

	// not OK or ERR :(
	return nil, ErrBadKSMResponse
}
