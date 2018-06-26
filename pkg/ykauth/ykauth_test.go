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
	"errors"
	"fmt"
	"testing"

	"github.com/conformal/yubikey"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

// nolint:golint,gochecknoglobals
var newYKAuthEntries = []struct {
	options []func(*YKAuth)
	timeout int
	sync    ykval.SyncValue
}{
	{[]func(*YKAuth){}, ykval.SyncTimeout, ykval.SyncDefault},
	{[]func(*YKAuth){SyncOpt(ykval.SyncFast)}, ykval.SyncTimeout, ykval.SyncFast},
	{[]func(*YKAuth){SyncOpt(ykval.SyncSecure)}, ykval.SyncTimeout, ykval.SyncSecure},
}

func TestNewYKAuth(t *testing.T) {
	for i, entry := range newYKAuthEntries {
		ykauth := NewYKAuth(nil, entry.options...)
		if ykauth.timeout != entry.timeout || ykauth.sync != entry.sync {
			t.Errorf("NewYKAuth() with entry: %d => "+
				"want timeout: %d, sync: %d - got timeout: %d, sync: %d",
				i, entry.timeout, entry.sync, ykauth.timeout, ykauth.sync,
			)
		}
	}
}

func TestAuthenticateInvalidOTP(t *testing.T) {
	client := &yubico.Client{}
	ykauth := NewYKAuth(client)
	want := yubikey.ErrInvalidOTPString
	got := ykauth.Authenticate("foo", "bar", "qux")
	if got != want {
		t.Errorf("Authenticate(%q, %q, %q) => want %s, got %s",
			"foo", "bar", "qux",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestAuthenticateInvalidUser(t *testing.T) {
	otp := "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"
	client := &yubico.Client{}
	ykauth := NewYKAuth(client)
	want := fmt.Errorf("dumb loader")
	got := ykauth.Authenticate("foo", "bar", otp)
	if !internal.ErrEqual(want, got) {
		t.Errorf("Authenticate(%q, %q, %q) => want %s, got %s",
			"foo", "bar", otp,
			internal.TestError(want), internal.TestError(got))
	}
}

func TestAuthenticateInvalidPassword(t *testing.T) {
	otp := "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"
	user := &yubico.User{
		// openssl passwd -5 <(echo foo)
		Hash: "$5$0THN5OEWkGvvUfAf$FdlC6utzlDHAIsiAuZ6.t8c7uIZKwIJXlPIWbJr0Mk2",
	}
	client := &yubico.Client{}
	ykauth := NewYKAuth(client, func(y *YKAuth) {
		y.UserLoader = yubico.UserLoaderFunc(func(string, string) (*yubico.User, error) {
			return user, nil
		})
	})
	want := ErrInvalidPassword
	got := ykauth.Authenticate("foo", "bar", otp)
	if want != got {
		t.Errorf("Authenticate(%q, %q, %q) => want %s, got %s",
			"foo", "bar", otp,
			internal.TestError(want), internal.TestError(got))
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	otp := "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"
	ykauth := NewYKAuth(&yubico.Client{}, func(y *YKAuth) {
		y.UserLoader = yubico.UserLoaderFunc(func(string, string) (*yubico.User, error) {
			return &yubico.User{
				// openssl passwd -5 <(echo foo)
				Hash: "$5$0THN5OEWkGvvUfAf$FdlC6utzlDHAIsiAuZ6.t8c7uIZKwIJXlPIWbJr0Mk2",
			}, nil
		})
	})
	if got := ykauth.Authenticate("foo", "foo", otp); got != nil {
		t.Errorf("Authenticate(%q, %q, %q) => want %s, got %s",
			"foo", "foo", otp,
			internal.TestError(nil), internal.TestError(got))
	}
}

func TestAuthorizeNonceFail(t *testing.T) {
	ykauth := NewYKAuth(&yubico.Client{}, func(y *YKAuth) {
		y.UserLoader = yubico.UserLoaderFunc(func(name, public string) (*yubico.User, error) {
			return &yubico.User{Name: name, Hash: ""}, nil
		})
		y.NonceFunc = func(int) (string, error) { return "", internal.ErrNoop }
	})
	want := internal.ErrNoop
	got := ykauth.Authorize("foo", "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh")
	if want != got {
		t.Errorf("Authorize(%q, %q) => want %s, got %s", "foo", "foo",
			internal.TestError(want), internal.TestError(got))
	}
}

//nolint:golint,gochecknoglobals
var authorizeTests = []struct {
	name    string
	user    string
	opt     string
	ykAuth  *YKAuth
	wantErr error
}{
	{
		name: "TestAuthorizeSuccess",
		user: "test",
		opt:  "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh",
		ykAuth: NewYKAuth(&yubico.Client{}, func(y *YKAuth) {
			y.Verifier = ykval.VerifierFunc(func(ykval.VerifyRequest) (*yubico.Yubikey, error) {
				return nil, nil
			})
			y.UserLoader = yubico.UserLoaderFunc(func(name, public string) (*yubico.User, error) {
				return &yubico.User{Name: name, Hash: ""}, nil
			})
		}),
		wantErr: nil,
	},
	{
		name:    "TestAuthorize-OPTParseFailure",
		user:    "test",
		opt:     "",
		ykAuth:  NewYKAuth(&yubico.Client{}),
		wantErr: errors.New("yubikey: invalid OTP string"),
	},
	{
		name: "TestAuthorize-LoadUserFailure",
		user: "test",
		opt:  "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh",
		ykAuth: NewYKAuth(&yubico.Client{}, func(y *YKAuth) {
			y.UserLoader = yubico.UserLoaderFunc(func(name, public string) (*yubico.User, error) {
				return nil, errors.New("unknown user")
			})
		}),
		wantErr: errors.New("unknown user"),
	},
	{
		name: "TestAuthorize-DumbVerifier",
		user: "test",
		opt:  "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh",
		ykAuth: NewYKAuth(&yubico.Client{}, func(y *YKAuth) {
			y.UserLoader = yubico.UserLoaderFunc(func(name, public string) (*yubico.User, error) {
				return &yubico.User{Name: name}, nil
			})
		}),
		wantErr: errors.New("dumb verifier"),
	},
}

func TestAuthorize(t *testing.T) {
	for _, tt := range authorizeTests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ykAuth.Authorize(tt.name, tt.opt); (err != nil) && !internal.ErrEqual(tt.wantErr, err) {
				t.Errorf("Authorize() expected error %v. Got %v", tt.wantErr, err)
			}
		})
	}
}
