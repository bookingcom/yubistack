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
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

// DecryptHandler is a structure embedding a DecrypterFactory and serving it as http
type DecryptHandler struct {
	ykksm.DecrypterFactory
}

// NewDecryptHandler creates a new DecryptHandler with sensible defaults
func NewDecryptHandler(options ...func(handler *DecryptHandler)) *DecryptHandler {
	dh := &DecryptHandler{
		DecrypterFactory: func(zerolog.Logger) ykksm.Decrypter {
			return ykksm.DecrypterFunc(func(string) (*yubico.Token, error) {
				return nil, fmt.Errorf("dumb decrypter")
			})
		},
	}
	for _, option := range options {
		option(dh)
	}
	return dh
}

// Handle implements the pkg.Handle interface and decrypt a token over http.
func (dh *DecryptHandler) Handle(ctx *Context) error {
	if err := ctx.ParseForm(); err != nil {
		return ctx.Error(err.Error(), http.StatusBadRequest)
	}

	token, err := dh.DecrypterFactory(ctx.Logger).Decrypt(ctx.FormValue("otp"))
	if err != nil {
		return err
	}
	ctx.Writef("OK counter=%04x low=%04x high=%02x use=%02x",
		token.Ctr, token.Tstpl, token.Tstph, token.Use,
	)
	return nil
}

type (
	// VerifyHandler is a http.Handler responsible for the verification of tokens
	VerifyHandler struct {
		ykval.VerifierFactory
		ClientLoaderFactory
	}

	// ClientLoaderFactory is currying a ClientLodaer to inject a logger on each request
	ClientLoaderFactory func(zerolog.Logger) yubico.ClientLoader
)

// NewVerifyHandler creates a new VerifyHandler with sensible defaults
func NewVerifyHandler(options ...func(handler *VerifyHandler)) *VerifyHandler {
	vh := &VerifyHandler{
		VerifierFactory: func(zerolog.Logger) ykval.Verifier {
			return ykval.VerifierFunc(func(ykval.VerifyRequest) (*yubico.Yubikey, error) {
				return nil, fmt.Errorf("dumb verifier")
			})
		},
		ClientLoaderFactory: func(zerolog.Logger) yubico.ClientLoader {
			return yubico.ClientLoaderFunc(func(uint64) (*yubico.Client, error) {
				return nil, fmt.Errorf("dumb client loader")
			})
		},
	}
	for _, option := range options {
		option(vh)
	}
	return vh
}

// Handle implements the pkg.Handle interface and verify a token over http.
func (vh *VerifyHandler) Handle(ctx *Context) error {
	if err := ctx.Request.ParseForm(); err != nil {
		return ctx.Error(err.Error(), http.StatusBadRequest)
	}
	req, err := ykval.ParseVerifyRequest(ctx.Logger, vh.ClientLoaderFactory(ctx.Logger), ctx.Request.Form)
	if err != nil {
		return err
	}

	ykey, err := vh.VerifierFactory(ctx.Logger).Verify(req)
	if err != nil {
		return err
	}
	ctx.Writef("%s timestamp=%d", ykval.Ok, time.Now().Unix())

	if req.Timestamp { // this is the yubico way of asking for more info
		ctx.Writef(" counter=%04x use=%02x", ykey.Counter, ykey.Use)
	}
	return nil
}

// SyncHandler is a structure embedding a SynchronizerFactory and serving it as http
type SyncHandler struct {
	ykval.SynchronizerFactory
	ClientLoaderFactory
}

// NewSyncHandler creates a new SyncHandler with sensible defaults
func NewSyncHandler(options ...func(handler *SyncHandler)) *SyncHandler {
	sh := &SyncHandler{
		SynchronizerFactory: func(zerolog.Logger) ykval.Synchronizer {
			return ykval.SynchronizerFunc(func(ykval.SyncRequest) (*yubico.Yubikey, error) {
				return nil, fmt.Errorf("dumb synchronizer")
			})
		},
		ClientLoaderFactory: func(zerolog.Logger) yubico.ClientLoader {
			return yubico.ClientLoaderFunc(func(uint64) (*yubico.Client, error) {
				return nil, fmt.Errorf("dumb client loader")
			})
		},
	}
	for _, option := range options {
		option(sh)
	}
	return sh
}

// Handle implements the pkg.Handle interface and synchronize a token over http.
func (sh *SyncHandler) Handle(ctx *Context) error {
	if err := ctx.ParseForm(); err != nil {
		return ctx.Error(err.Error(), http.StatusBadRequest)
	}
	req, err := ykval.ParseSyncRequest(ctx.Logger, sh.ClientLoaderFactory(ctx.Logger), ctx.Form)
	if err != nil {
		return err
	}
	ykey, err := sh.SynchronizerFactory(ctx.Logger).Synchronize(req)
	if err != nil {
		return err
	}
	ctx.Writef(ykval.SyncResp, ykey.Counter, ykey.Use, ykey.High, ykey.Low)
	return nil
}

type (
	// AuthHandler is a structure embedding authentication and authorization and serving it as http
	AuthHandler struct {
		AuthentifierFactory
		AuthorizerFactory
	}
	// AuthentifierFactory is currying an Authentifier to inject a logger on each request
	AuthentifierFactory func(zerolog.Logger) ykauth.Authentifier
	// AuthorizerFactory is currying an Authorizer to inject a logger on each request
	AuthorizerFactory func(zerolog.Logger) ykauth.Authorizer
)

// NewAuthHandler creates a new AuthHandler with sensible defaults
func NewAuthHandler(options ...func(handler *AuthHandler)) *AuthHandler {
	ah := &AuthHandler{
		AuthentifierFactory: func(zerolog.Logger) ykauth.Authentifier {
			return ykauth.AuthentifierFunc(func(_, _, _ string) error {
				return fmt.Errorf("dumb authentifier")
			})
		},
		AuthorizerFactory: func(zerolog.Logger) ykauth.Authorizer {
			return ykauth.AuthorizerFunc(func(_, _ string) error {
				return fmt.Errorf("dumb authorizer")
			})
		},
	}
	for _, option := range options {
		option(ah)
	}
	return ah
}

// Handle implements the pkg.Handle interface and perform authenticate and authorize over http.
func (ah *AuthHandler) Handle(ctx *Context) error {
	if err := ctx.ParseForm(); err != nil {
		return ctx.Error(err.Error(), http.StatusBadRequest)
	}
	otp, name := ctx.FormValue("otp"), ctx.FormValue("username")
	if values := ctx.Form["password"]; len(values) == 1 {
		if err := ah.AuthentifierFactory(ctx.Logger).Authenticate(name, values[0], otp); err != nil {
			return err
		}
	}
	if err := ah.AuthorizerFactory(ctx.Logger).Authorize(name, otp); err != nil {
		return err
	}
	ctx.Writef("OK")
	return nil
}
