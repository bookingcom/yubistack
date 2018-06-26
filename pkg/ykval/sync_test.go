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
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/util"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

// TODO: We may want to check against the log recorder entries
// it's a bit fragile and may need to be re-think

func TestSyncClientRequestFailure(t *testing.T) {
	recorder := &internal.LogRecords{}
	sc := NewSyncClient(func(sc *SyncClient) { sc.Logger = zerolog.Nop() })
	got := sc.Send("http://foo com")
	if !internal.YubikeyEqual(nil, got) {
		t.Log(recorder)
		t.Errorf("SyncClient.Send(%q) => want: %s, got %s",
			"/?%gh&%ij", internal.TestYubikey(nil), internal.TestYubikey(got))
	}
}

func TestSyncClientDoFailure(t *testing.T) {
	recorder := &internal.LogRecords{}
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		return nil, internal.ErrNoop
	})
	sc := NewSyncClient(func(sc *SyncClient) {
		sc.Logger = zerolog.Nop()
		sc.HTTPDoer = doer
	})
	got := sc.Send("http://foo.com")
	if !internal.YubikeyEqual(nil, got) {
		t.Log(recorder)
		t.Errorf("SyncClient.Send(%q) => want: %s, got %s",
			"/?%gh&%ij", internal.TestYubikey(nil), internal.TestYubikey(got))
	}
}

func TestSyncClientContextCancelled(t *testing.T) {
	recorder := &internal.LogRecords{}
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, &url.Error{Err: r.Context().Err()}
	})
	sc := NewSyncClient(func(sc *SyncClient) {
		sc.Logger = zerolog.Nop()
		sc.HTTPDoer = doer
		sc.context, sc.cancel = context.WithTimeout(context.Background(), 10*time.Second)
	})
	sc.Cancel()
	got := sc.Send("http://foo.com")
	if !internal.YubikeyEqual(nil, got) && len(*recorder) == 0 {
		t.Log(recorder)
		t.Errorf("SyncClient.Send(%q) with context canceled => want: %s, got %s",
			"/?%gh&%ij", internal.TestYubikey(nil), internal.TestYubikey(got))
	}
}

func TestSyncClientUrlFailure(t *testing.T) {
	recorder := &internal.LogRecords{}
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Err: internal.ErrNoop}
	})
	sc := NewSyncClient(func(sc *SyncClient) {
		sc.Logger = zerolog.Nop()
		sc.HTTPDoer = doer
	})
	got := sc.Send("http://foo.com")
	if !internal.YubikeyEqual(nil, got) && len(*recorder) == 0 {
		t.Log(recorder)
		t.Errorf("SyncClient.Send(%q) with url error => want: %s, got %s",
			"/?%gh&%ij", internal.TestYubikey(nil), internal.TestYubikey(got))
	}
}

func TestSyncClientBodyReadFailure(t *testing.T) {
	recorder := &internal.LogRecords{}
	resp := &http.Response{Body: ioutil.NopCloser(
		util.ReaderFunc(func([]byte) (int, error) { return 0, internal.ErrNoop }),
	)}
	doer := HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
		return resp, nil
	})
	sc := NewSyncClient(func(sc *SyncClient) {
		sc.Logger = zerolog.Nop()
		sc.HTTPDoer = doer
	})
	got := sc.Send("http://foo.com")
	if !internal.YubikeyEqual(nil, got) {
		t.Log(recorder)
		t.Errorf("SyncClient.Send(%q) => want: %s, got %s",
			"/?%gh&%ij", internal.TestYubikey(nil), internal.TestYubikey(got))
	}
}

//nolint:golint,gochecknoglobals
var syncClientResponseParsingEntries = []struct {
	status int
	body   string
	want   *yubico.Yubikey
}{
	{400, "foo", nil},
	{400, "ERR foo", nil},
	{200, "foo", nil},
	{200, "OK foo", nil},
	{200, "OK counter=0 use=0 high=0 low=0", &yubico.Yubikey{}},
}

func TestSyncClientResponseParsing(t *testing.T) {
	var resp *http.Response
	recorder := &internal.LogRecords{}
	sc := NewSyncClient(func(sc *SyncClient) {
		sc.Logger = zerolog.Nop()
		sc.HTTPDoer = HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
			return resp, nil
		})
	})
	for _, entry := range syncClientResponseParsingEntries {
		resp = &http.Response{
			StatusCode: entry.status,
			Body:       ioutil.NopCloser(bytes.NewBufferString(entry.body)),
		}
		got := sc.Send("http://foo.com")
		if !internal.YubikeyEqual(entry.want, got) {
			t.Log(recorder)
			t.Errorf("SyncClient.Send() => want: %s, got %s",
				internal.TestYubikey(nil), internal.TestYubikey(got))
		}
	}
}

func TestSyncClientCancel(t *testing.T) {
	sc := NewSyncClient(SyncClientTimeoutOpt(5), func(sc *SyncClient) {
		sc.HTTPDoer = HTTPDoerFunc(func(r *http.Request) (*http.Response, error) {
			<-sc.Context().Done()
			return nil, internal.ErrNoop
		})
	})
	go func() {
		time.Sleep(500 * time.Millisecond)
		sc.Cancel()
	}()

	start := time.Now()
	sc.Send("foo.com")
	got := time.Since(start)
	if got.Seconds() < 0.5 || got.Seconds() > 0.6 {
		t.Errorf("SyncClient.Send().Cancel() => want: ~%0.2f, got: %0.2f",
			0.5, got.Seconds())
	}
}

func baseReqEqual(br1, br2 BaseRequest) bool {
	return br1.ID == br2.ID && br1.OTP == br2.OTP
}
func syncReqEqual(sr1, sr2 SyncRequest) bool {
	return baseReqEqual(sr1.BaseRequest, sr2.BaseRequest) &&
		sr1.Counter == sr2.Counter && sr1.Use == sr2.Use &&
		sr1.Low == sr2.Low && sr1.High == sr2.High
}
func TestSyncClientSyncReqOpt(t *testing.T) {
	br := BaseRequest{ID: 1, OTP: "foo"}
	yk := &yubico.Yubikey{Counter: 2, Use: 3, Low: 4, High: 5}
	sc := NewSyncClient(func(sc *SyncClient) { sc.SyncRequest = CreateSync(VerifyRequest{BaseRequest: br}, yk) })
	want := SyncRequest{br, 2, 3, 4, 5, 0}
	got := sc.SyncRequest
	if !syncReqEqual(want, got) {
		t.Errorf("SyncClientSyncReqOpt(req: {id: %d, otp: %q}, key: {%s}) "+
			"=> want: %#v, got: %#v", br.ID, br.OTP, yk, want, got)
	}
}
