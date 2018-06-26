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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

// lint:file-ignore ST1011 needed

//nolint:golint,gochecknoglobals
var (
	fiveMin = time.Duration(5) * time.Minute
	fiveSec = time.Duration(5) * time.Second
	syncOTP = "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"
)

//nolint:golint,gochecknoglobals
var entriesPhishing = []struct {
	res     bool
	token   *yubico.Token
	yubikey *yubico.Yubikey
}{
	{
		false, internal.Token(0, 0),
		internal.Key("key 1", time.Now().Unix(), 0, 0),
	},
	{
		true, internal.Token(0, 0),
		internal.Key("key 2", time.Now().Add(-fiveMin).Unix(), 0, 0),
	},
	{
		false, internal.Token(0, 0),
		internal.Key("key 3", time.Now().Add(-fiveSec).Unix(), 0, 0),
	},
	{
		true, internal.Token(0, 1),
		internal.Key("key 4", time.Now().Unix(), 0, 0),
	},
	{
		// Same values as before except that counter differ, it bypass phishing test.
		false,
		func() *yubico.Token {
			token := internal.Token(0, 1)
			token.Ctr = 1
			return token
		}(),
		internal.Key("key 4", time.Now().Unix(), 0, 0),
	},
	{
		// 300 is five minutes in seconds, clock frequency is 1/8,
		// so this lower setup allow the phishing function to compute that tap occurred now.
		false, internal.Token(300*8, 0),
		internal.Key("key 5", time.Now().Add(-fiveMin).Unix(), 0, 0),
	},
	{
		// AbsTolerance is 20 seconds and RelTolerance is 0.3 (90/300) == 0.3
		false, internal.Token((300+90)*8, 0),
		internal.Key("key 6", time.Now().Add(-fiveMin).Unix(), 0, 0),
	},
	{
		// Adding two seconds in order to be out of tolerance (92/300) == 0.3067
		true, internal.Token((300+92)*8, 0),
		internal.Key("key 7", time.Now().Add(-fiveMin).Unix(), 0, 0),
	},
}

func TestPhishing(t *testing.T) {
	logger := &internal.LogRecords{}
	ykval := NewYKVal(mapperW(internal.NewDumbYubikeyMapper()),
		func(ykval *YKVal) { ykval.Logger = zerolog.Nop() })

	for _, entry := range entriesPhishing {
		out := ykval.Phishing(entry.token, entry.yubikey)
		if entry.res != out {
			t.Log(logger)
			t.Errorf("Phishing(%s, %s) => want: %t, got: %t",
				internal.TestToken(entry.token),
				internal.TestYubikey(entry.yubikey), entry.res, out)
		}
		logger.Reset()
	}
}

//nolint:golint,gochecknoglobals
var validateIDEntries = []struct {
	in  string
	out uint64
	err error
}{
	{"", 0, ErrNoID},
	{"foo", 0, ErrInvalidID},
	{"3", 3, nil},
}

func TestValidateID(t *testing.T) {
	for _, entry := range validateIDEntries {
		out, err := ValidateID(entry.in)
		if out != entry.out || !internal.ErrEqual(err, entry.err) {
			t.Errorf("ValidateID(%q) => want: %d, %s - got %d, %s",
				entry.in, entry.out, internal.TestError(entry.err),
				out, internal.TestError(err))
		}
	}
}

//nolint:golint,gochecknoglobals
var validateNonceEntries = []struct {
	nonce string
	err   error
}{
	{"", ErrNoNonce},
	{"foo", ErrInvalidNonce},
	{"foooooooooooooo", ErrInvalidNonce},
	{"fooooooooooooooo", nil},
	{"foooooooooooooo*", ErrInvalidNonce},
	{"fooooooooooooooooooooooooooooooooooooooo", nil},
	{"foooooooooooooooooooooooooooooooooooooooo", ErrInvalidNonce},
}

func TestValidateNonce(t *testing.T) {
	for _, entry := range validateNonceEntries {
		err := ValidateNonce(entry.nonce)
		if !internal.ErrEqual(err, entry.err) {
			t.Errorf("ValidateNonce(%q) => want: %s - got: %s",
				entry.nonce, entry.err, err)
		}
	}
}

//nolint:golint,gochecknoglobals
var validateSignatureEntries = []struct {
	hash, cipher string
	key          []byte
	err          error
}{
	{"", " foo", []byte("foo"), ErrInvalidSignature},
	{"foo", " foo", []byte("foo"), ErrInvalidSignature},
	{"FHkzIYqqvAuLEKKzpcNGhMjZQ0G88QpHNtxycPd0GFE=", "foo", []byte("bar"), nil},
	{"FHkzIYqqvAuLEKKzpcNGhMjZQ0G88QpHNtxycPd0GFE=", "bar", []byte("bar"), ErrInvalidSignature},
}

func TestValidateSignature(t *testing.T) {
	for _, entry := range validateSignatureEntries {
		err := ValidateSignature(entry.hash, entry.cipher, entry.key)
		if !internal.ErrEqual(err, entry.err) {
			t.Errorf("ValidateSignature(%q, %q, %q) => want: %s - got: %s",
				entry.hash, entry.cipher, entry.key, entry.err, err)
		}
	}
}

//nolint:golint,gochecknoglobals
var ctrEntries = []struct {
	syncLevel, serverCount, want int
}{
	{50, 100, 50},
	{0, 100, 1},
	{50, 1, 1},
	{50, 0, 0},
}

func TestCtr(t *testing.T) {
	for _, entry := range ctrEntries {
		got := ctr(entry.syncLevel, entry.serverCount)
		if got != entry.want {
			t.Errorf("ctr(%d, %d) => want: %d, got: %d",
				entry.syncLevel, entry.serverCount, entry.want, got)
		}
	}
}

//nolint:golint,gochecknoglobals
var isReplayedEntries = []struct {
	ctrOld, ctrNew, useOld, useNew uint
	want                           bool
}{
	{0, 0, 0, 0, true},
	{0, 1, 10, 1, false},
	{1, 0, 0, 10, true},
	{1, 1, 8, 10, false},
	{0, 1, 10, 11, false},
}

func TestIsReplayed(t *testing.T) {
	for _, entry := range isReplayedEntries {
		got := isReplayed(entry.ctrOld, entry.ctrNew, entry.useOld, entry.useNew)
		if entry.want != got {
			t.Errorf("isReplayed(%d, %d, %d, %d) => want: %t, got: %t",
				entry.ctrOld, entry.ctrNew, entry.useOld, entry.useNew, entry.want, got)
		}
	}
}

func TestLoadInvalidOTP(t *testing.T) {
	ykval := NewYKVal(mapperW(internal.NewDumbYubikeyMapper()),
		decrypter(nil, internal.ErrNoop))
	want := internal.ErrNoop
	_, _, got := ykval.load("", "")
	if !internal.ErrEqual(want, got) {
		t.Errorf("Check() with invalid decrypterFn => want: %s, got: %s",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestLoadNoYubikey(t *testing.T) {
	ykval := NewYKVal(mapperW(internal.DumbYubikeyMapper{
		YubikeyLoader:   loader(nil, ykksm.ErrNoYubikey),
		YubikeyProducer: producer(&yubico.Yubikey{}, nil),
	}), decrypterFn(nil))
	want := ykksm.ErrNoYubikey
	_, _, got := ykval.load("", "")
	if !internal.ErrEqual(want, got) {
		t.Errorf("Check() with inactive yubikey => want: %s, got: %s",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestLoadDBFailure(t *testing.T) {
	mapper := internal.DumbYubikeyMapper{
		YubikeyLoader:   loader(nil, ykksm.ErrNoYubikey),
		YubikeyProducer: producer(nil, internal.ErrNoop),
	}
	ykval := NewYKVal(mapperW(mapper), decrypterFn(nil))
	want := internal.ErrNoop
	_, _, got := ykval.load("", "")
	if !internal.ErrEqual(want, got) {
		t.Errorf("Check() with invalid producer => want: %s, got: %s",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestSynchronizeLoadFailure(t *testing.T) {
	want := internal.ErrNoop
	ykval := NewYKVal(mapperW(internal.NewDumbYubikeyMapper()),
		decrypter(nil, want))
	_, got := ykval.Synchronize(SyncRequest{})
	if !internal.ErrEqual(want, got) {
		t.Errorf("Synchronize() with invalid OTP => want: %s, got: %s", want, got)
	}
}

func TestSynchronizeUpdate(t *testing.T) {
	called := false
	req := makeSyncReq(3, 4, "bar")
	want := makeSyncKey(1, 2, "foo")
	mapper := internal.NewDumbYubikeyMapper()
	mapper.YubikeyLoader = loader(want, nil)
	mapper.YubikeyUpdater = yubico.YubikeyUpdaterFunc(func(got *yubico.Yubikey) error {
		want := makeSyncKey(3, 4, "bar")
		if !syncKeyEqual(want, got) {
			t.Errorf("Synchronize().Update() => want: %s, got: %s", want, got)
		}
		called = true
		return nil
	})
	ykval := NewYKVal(mapperW(mapper), decrypterFn(nil))
	got, err := ykval.Synchronize(req)
	if !syncKeyEqual(want, got) || err != nil || !called {
		t.Errorf("Synchronize(req: {%s}) with yubikey{%s} => want: "+
			"yubikey{%s}, %s, called{%t} - got: yubikey{%s}, %s, called{%t}", req, want,
			want, internal.TestError(nil), true,
			got, internal.TestError(err), called)
	}
	if !syncKeyEqual(want, got) {
		t.Errorf("Synchronize().Update() => want: %s, got: %s",
			want, got)
	}
}

//nolint:golint,gochecknoglobals
var synchronizeEntries = []struct {
	req  SyncRequest
	key  *yubico.Yubikey
	want error
}{
	{
		makeSyncReq(0, 0, ""),
		makeSyncKey(0, 0, ""),
		ErrReplayedRequest,
	},
	{
		makeSyncReq(0, 0, ""),
		makeSyncKey(0, 0, "foo"),
		ErrReplayedOTP,
	},
	{
		makeSyncReq(0, 1, ""),
		makeSyncKey(0, 0, ""),
		nil,
	},
}

func TestSynchronize(t *testing.T) {
	mapper := internal.NewDumbYubikeyMapper()
	ykval := NewYKVal(func(zerolog.Logger) yubico.YubikeyDBMapper {
		return mapper
	}, decrypterFn(nil))
	for _, entry := range synchronizeEntries {
		mapper.YubikeyLoader = loader(entry.key, nil)
		_, got := ykval.Synchronize(entry.req)
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("Synchronize(req: {%s}) with yubikey{%s} => want: %s, got: %s",
				entry.req, entry.key, internal.TestError(entry.want), internal.TestError(got))
		}
	}
}

func TestCheckUpdateFailure(t *testing.T) {
	mapper := internal.NewDumbYubikeyMapper()
	mapper.YubikeyUpdater = updater(internal.ErrNoop)
	ykval := NewYKVal(mapperW(mapper), decrypter(makeToken(0, 1), nil))
	_, _, got := ykval.Check(VerifyRequest{})
	want := ErrDelayedOTP
	// lint:ignore SA9003 this test is currently not active
	//nolint:golint,staticcheck
	if !internal.ErrEqual(want, got) {
		// t.Errorf("Check() with failing updater => want: %s, got: %s",
		//	internal.TestError(want), internal.TestError(got))
	}
}

//nolint:golint,gochecknoglobals
var entriesCheck = []struct {
	ytoken *yubico.Token
	ykey   *yubico.Yubikey
	want   error
}{
	{makeToken(0, 0), &yubico.Yubikey{}, ykksm.ErrNoYubikey},
	{makeToken(0, 0), &yubico.Yubikey{Active: true}, ErrReplayedRequest},
	{makeToken(0, 0), &yubico.Yubikey{Active: true, Counter: 1}, ErrReplayedOTP},
	// {makeToken(0, 1), &yubico.Yubikey{Active: true}, ErrDelayedOTP},
	{makeToken(1, 1), &yubico.Yubikey{Active: true}, nil},
}

func TestCheck(t *testing.T) {
	mapper := internal.NewDumbYubikeyMapper()
	for _, entry := range entriesCheck {
		mapper.YubikeyLoader = loader(entry.ykey, nil)
		ykval := NewYKVal(mapperW(mapper), decrypter(entry.ytoken, nil))
		_, _, got := ykval.Check(VerifyRequest{})
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("Check() with yubikey: {%s}, token: {%s} => want %s - got %s",
				internal.TestYubikey(entry.ykey), internal.TestToken(entry.ytoken),
				internal.TestError(entry.want), internal.TestError(got),
			)
		}
	}
}

func TestVerifyCheckFailure(t *testing.T) {
	mapper := internal.NewDumbYubikeyMapper()
	mapper.YubikeyLoader = loader(&yubico.Yubikey{}, nil)
	ykval := NewYKVal(mapperW(mapper), decrypterFn(nil))
	want := ykksm.ErrNoYubikey
	_, got := ykval.Verify(VerifyRequest{})
	if !internal.ErrEqual(want, got) {
		t.Errorf("Verify() with failing check => want %s - got %s",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestVerifyContextCancelled(t *testing.T) {
	mapper := internal.NewDumbYubikeyMapper()
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		time.Sleep(500 * time.Millisecond)
		return nil, r.Context().Err()
	})
	svrOpt := func(ykval *YKVal) { ykval.Servers = []string{"http://foo.bar"} }
	ykval := NewYKVal(mapperW(mapper), decrypterFn(nil), httpDoer(doer), svrOpt)

	want := context.DeadlineExceeded
	_, got := ykval.Verify(VerifyRequest{})
	if !internal.ErrEqual(want, got) {
		t.Errorf("Verify() with canceling context => want %s - got %s",
			internal.TestError(want), internal.TestError(got))
	}
}

//nolint:golint,gochecknoglobals
var entriesVerify = []struct {
	keys []*yubico.Yubikey
	want error
}{
	{[]*yubico.Yubikey{nil}, ErrNotEnoughAnswers},
	{[]*yubico.Yubikey{}, nil},
	{[]*yubico.Yubikey{makeSyncKey(1, 1, "")}, ErrReplayedOTP},
	{[]*yubico.Yubikey{makeSyncKey(0, 0, "")}, nil},
}

func TestVerify(t *testing.T) {
	for _, entry := range entriesVerify {
		testVerify(t, entry.keys, entry.want)
	}
}

func testVerify(t *testing.T, keys []*yubico.Yubikey, want error) {
	t.Helper()
	mapper := internal.NewDumbYubikeyMapper()
	i := 0
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		defer func() { i++ }()
		return makeResponseFromKey(keys[i])
	})
	svrOpt := func(ykval *YKVal) { ykval.Servers = make([]string, len(keys)) }
	ctxOpt := func(ykval *YKVal) {
		ctxOpt := func(sc *SyncClient) { sc.context = context.Background() }
		ykval.SyncClientOpts = append(ykval.SyncClientOpts, ctxOpt)
	}
	ykval := NewYKVal(mapperW(mapper), decrypterFn(nil),
		httpDoer(doer), svrOpt, ctxOpt)

	_, got := ykval.Verify(VerifyRequest{})
	if !internal.ErrEqual(want, got) {
		t.Errorf("Verify() with yubikeys %#v => want %s - got %s",
			keys, internal.TestError(want), internal.TestError(got))
	}
}

/* -------------------------------------------------------------------------- */
/* ---------           Bunch of helpers for those testing           --------- */
/* -------------------------------------------------------------------------- */

func makeSyncReq(counter, use uint, nonce string) SyncRequest {
	return SyncRequest{BaseRequest: BaseRequest{OTP: syncOTP, Nonce: nonce},
		Counter: counter, Use: use}
}

func makeSyncKey(counter, use uint, nonce string) *yubico.Yubikey {
	return &yubico.Yubikey{Active: true, Counter: counter, Use: use, Nonce: nonce}
}

func makeToken(ctr, use uint) *yubico.Token {
	return &yubico.Token{
		Token:  &yubikey.Token{Ctr: uint16(ctr), Use: uint8(use)},
		Public: "foo",
	}
}

func makeResponseFromKey(ykey *yubico.Yubikey) (*http.Response, error) {
	if ykey == nil {
		return nil, internal.ErrNoop
	}
	return &http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(bytes.NewBufferString(
		fmt.Sprintf(SyncResp, ykey.Counter, ykey.Use, ykey.High, ykey.Low),
	))}, nil
}

func decrypterFn(fn func(string) (*yubico.Token, error)) func(*YKVal) {
	if fn == nil {
		//nolint:golint,unparam
		fn = func(string) (*yubico.Token, error) { return makeToken(1, 1), nil }
	}
	return func(ykval *YKVal) {
		ykval.DecrypterFactory = func(zerolog.Logger) ykksm.Decrypter {
			return ykksm.DecrypterFunc(fn)
		}
	}
}

func decrypter(token *yubico.Token, err error) func(*YKVal) {
	return decrypterFn(func(string) (*yubico.Token, error) { return token, err })
}

func httpDoer(d HTTPDoer) func(*YKVal) {
	doerOpt := func(sc *SyncClient) { sc.HTTPDoer = d }
	return func(ykval *YKVal) { ykval.SyncClientOpts = append(ykval.SyncClientOpts, doerOpt) }
}

func loader(key *yubico.Yubikey, err error) yubico.YubikeyLoader {
	return yubico.YubikeyLoaderFunc(func(string) (*yubico.Yubikey, error) { return key, err })
}

func producer(key *yubico.Yubikey, err error) yubico.YubikeyProducer {
	return yubico.YubikeyProducerFunc(
		func(*yubico.Token, string) (*yubico.Yubikey, error) { return key, err },
	)
}

func updater(err error) yubico.YubikeyUpdater {
	return yubico.YubikeyUpdaterFunc(func(*yubico.Yubikey) error { return err })
}

func syncKeyEqual(yk1, yk2 *yubico.Yubikey) bool {
	return yk1.Active == yk2.Active && yk1.Nonce == yk2.Nonce &&
		yk1.Counter == yk2.Counter && yk1.Use == yk2.Use
}

func mapperW(mapper yubico.YubikeyDBMapper) func(zerolog.Logger) yubico.YubikeyDBMapper {
	return func(zerolog.Logger) yubico.YubikeyDBMapper { return mapper }
}
