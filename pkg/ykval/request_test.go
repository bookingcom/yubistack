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

// Those tests requires you to generate hash from request values.
// In order to generate this we can use the following bash command:
//  echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh" \
//      | openssl dgst -sha256 -hmac "foo" -binary | base64
// You will need to put values in alphabetical order to generate the proper hashes.
package ykval

import (
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

type testLoader struct {
	zerolog.Logger
	yubico.ClientLoader
}

//nolint:golint,gochecknoglobals
var (
	testLoad = testLoader{
		log.Logger,
		yubico.ClientLoaderFunc(func(uint64) (*yubico.Client, error) {
			// printf "foo" |  base64
			return &yubico.Client{Secret: "Zm9v"}, nil
		}),
	}
)

func TestSyncRequestString(t *testing.T) {
	req := SyncRequest{BaseRequest: BaseRequest{ID: 3}}
	want := "id: 3, token: {pub: , ctr: 0, use: 0}"
	got := req.String()
	if want != got {
		t.Errorf("%#v.String() => want: %q, got: %q", req, want, got)
	}
}

func TestVerifyRequestString(t *testing.T) {
	req := VerifyRequest{BaseRequest: BaseRequest{ID: 3}, Timestamp: true, Sl: 2, Timeout: 3}
	want := "id: 3, timestamp: true, sync: 2, timeout: 3"
	got := req.String()
	if want != got {
		t.Errorf("%#v.String() => want: %q, got: %q", req, want, got)
	}
}

// Generated using
// echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var parseBaseRequestEntries = []struct {
	values url.Values
	want   error
}{
	{url.Values{}, ErrNoID},
	{url.Values{"id": {"foo"}}, ErrInvalidID},
	{url.Values{"id": {"1"}}, ykksm.ErrNoOTP},
	{url.Values{"otp": {"foo"}, "id": {"1"}}, ykksm.ErrInvalidOTP},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
		}, ErrNoNonce,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"foo"},
		}, ErrInvalidNonce,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "hash": {"foo"},
		}, ErrInvalidSignature,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "hash": {"u62DPQSQqFvyozMmzse3Ct0Emz/JvAk/tWBFAKM6G0Y="},
		}, nil,
	},
}

func TestParseBaseRequest(t *testing.T) {
	for _, entry := range parseBaseRequestEntries {
		_, got := ParseBaseRequest(testLoad.Logger, &testLoad, entry.values)
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf(
				"ParseBaseRequest(%+v) => want: %s - got: %s",
				entry.values, internal.TestError(entry.want), internal.TestError(got),
			)
		}
	}
}

func TestParseBaseRequestClientLoadFailure(t *testing.T) {
	values := url.Values{
		"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
		"nonce": {"fooooooooooooooooooo"},
	}
	loader := testLoader{
		log.Logger,
		yubico.ClientLoaderFunc(func(uint64) (*yubico.Client, error) {
			return nil, internal.ErrNoop
		}),
	}
	want := internal.ErrNoop
	_, got := ParseBaseRequest(loader.Logger, &loader, values)
	if want != got {
		t.Errorf(
			"ParseBaseRequest(%+v) => want: %s - got: %s",
			values, internal.TestError(want), internal.TestError(got),
		)
	}
}

// Generated using
// echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var parseSyncRequestEntries = []struct {
	values url.Values
	want   error
}{

	/* 0 */ {url.Values{}, ErrNoID},
	/* 1 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "hash": {"u62DPQSQqFvyozMmzse3Ct0Emz/JvAk/tWBFAKM6G0Y="},
		}, ErrMissingParameter,
	},
	/* 2 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"1"}, "high": {"1"}, "modified": {"1"}, "hash": {"iW01hVERcdHiQi7Y5eYRBriWZ28qHZKlLb+Lrk232Ns="},
		}, nil,
	},
	/* 3 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"foo"}, "use": {"1"},
			"low": {"1"}, "high": {"1"}, "modified": {"1"}, "hash": {"koEkX9z5ccFu1iPTDUgEYKOaxLE7jPXfBhtXyt48Ns8="},
		}, ErrMissingParameter,
	},
	/* 4 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"foo"},
			"low": {"1"}, "high": {"1"}, "modified": {"1"}, "hash": {"SZwEC467QieRE5Dnu3cN0IwpqwBxZkoKxLoLSQ0b0QY="},
		}, ErrMissingParameter,
	},
	/* 5 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"},
			"low": {"1"}, "high": {"1"}, "modified": {"1"}, "hash": {"0b8KuTDc+jTwpLc//EgcVh/Fyrv/fhgF9ZBdAwjaqW8="},
		}, ErrMissingParameter,
	},
	/* 6 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"foo"}, "high": {"1"}, "modified": {"1"}, "hash": {"C+gAFl5GnNsJq/qFZhhWsFbxe1JLCfkWWOxr5+tJU+Q="},
		}, ErrMissingParameter,
	},
	/* 7 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"high": {"1"}, "modified": {"1"}, "hash": {"qIvsy8g9ULy34/fxFfjU5vzTyLmwaWngMNWy+bq8L1g="},
		}, ErrMissingParameter,
	},
	/* 8 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"1"}, "high": {"foo"}, "modified": {"1"}, "hash": {"ECWGlDIeLs4rX6zThAWiDmCtxo+monYc39c3nwocMXo="},
		}, ErrMissingParameter,
	},
	/* 9 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"1"}, "modified": {"1"}, "hash": {"jxTAQlMyj4gIn0uohxsOTGGX/5R5TOX57vJrTi5E1tk="},
		}, ErrMissingParameter,
	},
	/* 10 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"1"}, "high": {"1"}, "modified": {"foo"}, "hash": {"4pUf/ukjl7N0ll3pUYv2zTbd++KPWlGtWNAHK4J/mYE="},
		}, ErrMissingParameter,
	},
	/* 11 */ {
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
			"low": {"1"}, "high": {"1"}, "hash": {"NNKI1DNG/0ES21Az0RKIOfZcyEtCYc2uNYO2uuz2Jc0="},
		}, ErrMissingParameter,
	},
}

func TestParseSyncRequest(t *testing.T) {
	for i, entry := range parseSyncRequestEntries {
		_, got := ParseSyncRequest(testLoad.Logger, &testLoad, entry.values)
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf(
				"[%d] ParseSyncRequest(%+v) => want: %s - got: %s", i,
				entry.values, internal.TestError(entry.want), internal.TestError(got),
			)
		}
	}
}

// Generated using
// echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&timeout=-4" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var parseVerifyRequestFailureEntries = []struct {
	values url.Values
	want   error
}{
	{url.Values{}, ErrNoID},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timeout": {"-4"}, "hash": {"ogoWsisjtqdzOiNMm5mlmk+ziWTP7u+ZSnm7sKnAyW4="},
		}, ErrInvalidTimeout,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timeout": {"foo"}, "hash": {"dQ+sZJKLSABz3H1K3OlNrs1Yng8eOSSoAdBm+JnBTz4="},
		}, ErrInvalidTimeout,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timeout": {"0"}, "hash": {"iFeFFl9n8dNZXpe0m2A8ySifQDyUg3ZO8GShkuEJdW8="},
		}, ErrInvalidTimeout,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timeout": {"-1"}, "hash": {"Ra+RoSYrtQ9aj3amt9fkWIwtQm1nF8XTuE7eKKq+W2M="},
		}, ErrInvalidTimeout,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"foo"}, "hash": {"1p3cSDhc0IFpbl8kwnVATL/ogfvObYSlxz3apPSwhoY="},
		}, ErrInvalidSync,
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"101"}, "hash": {"cGvz+J7WZ4ZGX5o5FdtkMxabnXVN/cpmfiAwu90bTzw="},
		}, ErrInvalidSync,
	},
}

func TestParseVerifyRequestFailure(t *testing.T) {
	for i, entry := range parseVerifyRequestFailureEntries {
		_, got := ParseVerifyRequest(zerolog.Nop(), &testLoad, entry.values)
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf(
				"[%d] ParseVerifyRequest(%+v) => want: %s - got: %s",
				i, entry.values, internal.TestError(entry.want), internal.TestError(got),
			)
		}
	}
}

// Generated using
// echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var parseVerifyRequestEntries = []struct {
	values url.Values
	want   VerifyRequest
}{
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "hash": {"u62DPQSQqFvyozMmzse3Ct0Emz/JvAk/tWBFAKM6G0Y="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, SyncDefault, SyncTimeout},
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timestamp": {"1"}, "hash": {"1NdG5Fgm3KaFyE7biKS94VqbMC+dI8ExmeWYiUNeEoE="},
		}, VerifyRequest{BaseRequest{ID: 1}, true, SyncDefault, SyncTimeout},
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timestamp": {"2"}, "hash": {"gk1DJdycXYqHBJ2waomVSxOBPJVI3ihrAdleVpkB4fU="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, SyncDefault, SyncTimeout},
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "timeout": {"4"}, "hash": {"HW9H8LFk5Briz/NtcSXL8YMeR9V+h2CN+Q8DZAUQr/w="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, SyncDefault, 4},
	},

	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"75"}, "hash": {"P3rzVTEXISUcnvClM8PdOQOqgShYYP25WZQkYP3iTNE="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, 75, SyncTimeout},
	},

	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"fast"}, "hash": {"M3BAcg5dupU65xkOGwOvI1khSpV1HU3L8b3B5iiU25g="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, SyncFast, SyncTimeout},
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"secure"}, "hash": {"dqYR2KjLGBDBW4tV1lTvdV0v15Dvl+jza09Bs7aLdes="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, SyncSecure, SyncTimeout},
	},
	{
		url.Values{
			"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
			"nonce": {"fooooooooooooooooooo"}, "sl": {"100"}, "hash": {"8WGjDSDpCoLp2PI01TMEU2KwneuW5Z+9jwDXrYCTtag="},
		}, VerifyRequest{BaseRequest{ID: 1}, false, 100, SyncTimeout},
	},
}

func TestParseVerifyRequest(t *testing.T) {
	requestEqual := func(vr1, vr2 VerifyRequest) bool {
		return vr1.Timestamp == vr2.Timestamp && vr1.Sl == vr2.Sl &&
			vr1.Timeout == vr2.Timeout
	}
	for i, entry := range parseVerifyRequestEntries {
		got, _ := ParseVerifyRequest(zerolog.Nop(), &testLoad, entry.values)
		if !requestEqual(entry.want, got) {
			t.Errorf("[%d] ParseVerifyRequest(%+v) => "+
				"want: VerifyReq{%s} - got: VerifyReq{%s}",
				i, entry.values, entry.want, got,
			)
		}
	}
}
