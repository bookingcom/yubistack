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
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
)

//nolint:golint,gochecknoglobals
var defaultErrorHandlerEntries = []struct {
	err  error
	code int
	msg  string
}{
	{nil, http.StatusOK, ""},
	{ErrSkip, http.StatusOK, ""},
	{ykval.ErrNoID, http.StatusBadRequest, "ERR MISSING_PARAMETER"},
	{ykval.ErrInvalidID, http.StatusBadRequest, "ERR MISSING_PARAMETER"},
	{ykksm.ErrNoOTP, http.StatusBadRequest, "ERR MISSING_PARAMETER"},
	{ykval.ErrNoNonce, http.StatusBadRequest, "ERR MISSING_PARAMETER"},
	{ykval.ErrInvalidNonce, http.StatusBadRequest, "ERR MISSING_PARAMETER"},
	{ykksm.ErrInvalidOTP, http.StatusBadRequest, "ERR BAD_OTP"},
	{ykksm.ErrCorruptOTP, http.StatusBadRequest, "ERR BAD_OTP"},
	{ykval.ErrDelayedOTP, http.StatusBadRequest, "ERR BAD_OTP"},
	{ykauth.ErrInvalidPassword, http.StatusBadRequest, "ERR BAD_OTP"},
	{ykval.ErrNoClient, http.StatusBadRequest, "ERR NO_SUCH_CLIENT"},
	{ykval.ErrInvalidSignature, http.StatusBadRequest, "ERR BAD_SIGNATURE"},
	{ykval.ErrReplayedOTP, http.StatusBadRequest, "ERR REPLAYED_OTP"},
	{ykval.ErrReplayedRequest, http.StatusBadRequest, "ERR REPLAYED_REQUEST"},
	{ykval.ErrNotEnoughAnswers, http.StatusInternalServerError,
		"ERR NOT_ENOUGH_ANSWERS"},
	{context.DeadlineExceeded, http.StatusInternalServerError,
		"ERR NOT_ENOUGH_ANSWERS"},
	{ykauth.ErrNoUser, http.StatusBadRequest, "ERR NO_USER"},
	{internal.ErrNoop, http.StatusInternalServerError, "ERR BACKEND_ERROR"},
}

func TestDefaultErrorHandler(t *testing.T) {
	for _, entry := range defaultErrorHandlerEntries {
		resp := httptest.NewRecorder()
		ctx := &Context{
			NewResponse(resp),
			httptest.NewRequest(http.MethodGet, "/foo", nil),
			log.Logger,
		}
		DefaultErrorHandler(ctx, entry.err)
		ctx.write()
		result := resp.Result()
		body := internal.ReadAll(t, result.Body)
		if result.StatusCode != entry.code || body != entry.msg {
			t.Errorf("DefaultErrorHandler(%s) => want %d, %q - got %d, %q",
				internal.TestError(entry.err), entry.code, entry.msg,
				result.StatusCode, body)
		}
	}
}

func TestMiddlewares(t *testing.T) {
	var got []string
	var want = []string{"start.a", "start.b", "end.b", "end.a"}
	var server = NewServer(func(s *Server) { s.Logger = log.Logger })
	var w, r = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)
	var middleware = func(suffix string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(ctx *Context) error {
				got = append(got, "start."+suffix)
				err := next(ctx)
				got = append(got, "end."+suffix)
				return err
			}
		}
	}

	server.Use(middleware("a"))
	server.Use(middleware("b"))
	server.Handle("/", HandlerFunc(func(ctx *Context) error { return nil }))
	server.Server.Handler.ServeHTTP(w, r)
	if !internal.StrSliceEqual(want, got) {
		t.Errorf("Middlewares(%q, %q) => want %+v, got %+v", "a", "b", want, got)
	}
}

func TestMiddlewareFailure(t *testing.T) {
	// var got = &internal.LogRecords{}
	// var want = &internal.LogRecords{
	//	{Level: ERROR, Format: "middleware error: %s",
	//		Args: []interface{}{internal.ErrNoop}},
	//	{Level: DEBUG, Format: "encoding response: %s", Args: []interface{}{"foo"}},
	// }
	var server = NewServer(func(s *Server) { s.Logger = zerolog.Nop() })
	var w, r = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)
	var middleware = func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error { return internal.ErrNoop }
	}

	server.Use(middleware)
	server.Handle("/", HandlerFunc(func(ctx *Context) error { return nil }))
	server.Server.Handler.ServeHTTP(w, r)
	// if !internal.LogRecordsEqual(want, got) {
	//	t.Errorf("MiddlewaresFailure() => want %s, got %s", want, got)
	// }
}

func TestServeFailedListening(t *testing.T) {
	var logger = &internal.LogRecords{}
	var server = NewServer(func(s *Server) { s.Logger = zerolog.Nop() })

	got := server.Serve("foo", "bar")
	want := fmt.Errorf("listen foo: unknown network foo")
	if !internal.ErrEqual(got, want) {
		t.Log(logger)
		t.Errorf("Serve({invalid http2 config}) => want %s, got %s",
			internal.TestError(want), internal.TestError(got))
	}
}

func TestServeFailedServing(t *testing.T) {
	var logger = &internal.LogRecords{}
	var server = NewServer(func(s *Server) {
		s.Logger = zerolog.Nop()
		s.TLSConfig = &tls.Config{NextProtos: []string{"h2"}, CipherSuites: []uint16{0}}
	})
	var err = internal.TempFileName(t, func(name string) error {
		got := server.Serve("unix", name)
		want := fmt.Errorf("http2: TLSConfig.CipherSuites is missing an " +
			"HTTP/2-required AES_128_GCM_SHA256 cipher " +
			"(need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or " +
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).") //nolint:golint
		if !internal.ErrEqual(got, want) {
			t.Log(logger)
			t.Errorf("Serve({invalid http2 config}) => want %s, got %s",
				internal.TestError(want), internal.TestError(got))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %q", err)
	}
}

func TestServe(t *testing.T) {
	var server = NewServer(func(s *Server) { s.Logger = zerolog.Nop() })
	var err = internal.TempFileName(t, func(name string) error {
		go func() {
			if err := server.Serve("unix", name); err != http.ErrServerClosed {
				t.Errorf("unexpected error want: %q, got: %q",
					http.ErrServerClosed, err)
			}
		}()
		return server.Shutdown(context.Background())
	})
	if err != nil {
		t.Errorf("Server.Serve() should have closed without error, got: %q", err)
	}
}

func TestListenAndServe(t *testing.T) {
	var logger = &internal.LogRecords{}
	var server = NewServer(func(s *Server) { s.Logger = zerolog.Nop() })
	var errListen, errShutdown error
	go func() { errListen = server.ListenAndServe() }()
	errShutdown = server.Shutdown(context.Background())

	if errShutdown != nil || errListen != nil {
		t.Log(logger)
		t.Errorf("Server().ListenAndServe() should have shutdown without error %q, %q",
			errListen, errShutdown)
	}
}

func TestHandleFuncErrHandler(t *testing.T) {
	var w, r = httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)
	var server = NewServer(func(s *Server) {
		s.Logger = zerolog.Nop()
		s.ErrorHandler = func(ctx *Context, err error) {
			got := ctx.Error(err.Error(), http.StatusInternalServerError)
			if !internal.ErrEqual(got, ErrSkip) {
				t.Errorf("ctx.Error() => want: %s, got %s",
					internal.TestError(ErrSkip), internal.TestError(got))
			}
		}
	})
	server.Handle("/", HandlerFunc(func(ctx *Context) error { return internal.ErrNoop }))
	server.Server.Handler.ServeHTTP(w, r)
	resp := w.Result()
	got := internal.ReadAll(t, resp.Body)
	want := "ERR " + internal.ErrNoop.Error()
	if resp.StatusCode != http.StatusInternalServerError || got != want {
		t.Errorf("ctx.Error().Response => want: %d, %s - got: %d, %s",
			http.StatusInternalServerError, want, resp.StatusCode, got)
	}
}

type FailingResp struct{}

func (fr FailingResp) Header() http.Header       { return http.Header{} }
func (fr FailingResp) Write([]byte) (int, error) { return 0, internal.ErrNoop }
func (fr FailingResp) WriteHeader(int)           {}

// TODO: bring back a testing case
func TestWriteErr(t *testing.T) {
	var w, r = FailingResp{}, httptest.NewRequest(http.MethodGet, "/", nil)
	var server = NewServer()
	server.Handle("/", HandlerFunc(func(ctx *Context) error {
		ctx.Writef("foo")
		return nil
	}))
	server.Server.Handler.ServeHTTP(w, r)
}

//nolint:golint,gochecknoglobals
var remoteHostEntries = []struct {
	addr string
	want string
}{
	{"127.0.0.1:80", "127.0.0.1"},
	{"127.0.0.1", "127.0.0.1"},
	{"golang.org:", "golang.org"},
	{"golang.org", "golang.org"},
}

func TestRemoteHost(t *testing.T) {
	for _, entry := range remoteHostEntries {
		ctx := &Context{Request: &http.Request{RemoteAddr: entry.addr}}
		got := ctx.RemoteHost()
		if got != entry.want {
			t.Errorf("RemoteHost() with %q => want: %q, got: %q",
				entry.addr, entry.want, got)
		}
	}
}
