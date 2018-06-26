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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
)

const (
	defaultAddr         = ":8080"
	defaultReadTimeout  = 5 * time.Second
	defaultWriteTimeout = 10 * time.Second
	defaultIdleTimeout  = 120 * time.Second

	// HeaderContent is constant extracted value of Content-Type header
	HeaderContent = "Content-Type"
	// HeaderAccept is constant extracted value of Accept header
	HeaderAccept = "Accept"

	// MimeText is constant extracted value of mimetype for text
	MimeText = "text/plain"
	// MimeJSON is constant extracted value of mimetype for text
	MimeJSON = "application/json"

	// FmtErr is yubico format for text error response
	FmtErr = "ERR %s"
)

var (
	// ErrSkip is the error used to notify that error has been handled
	ErrSkip = fmt.Errorf("error already handled")

	//nolint:golint,gochecknoglobals
	// TLS preferences
	preferredCiphers = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_AES_128_GCM_SHA256,
	}
	//nolint:golint,gochecknoglobals
	preferredCurves = []tls.CurveID{
		tls.X25519, // Go 1.8 only
		tls.CurveP256,
	}
)

type (
	// HandlerFunc is a wrapper for a function to implement the Handler interface
	HandlerFunc func(*Context) error

	// Handler is an interface we will use to handle HTTP requests
	Handler interface {
		Handle(*Context) error
	}
)

// Handle wraps a function to implement Handler interface
func (hf HandlerFunc) Handle(ctx *Context) error { return hf(ctx) }

// Context wraps most of the structures we want to pass down to the Handler
// It contains the stdlib ServeHTTP arguments: Request, Response and is
// enhanced with other services, for the moment only the Logger, but some
// may be added later (like DB or so).
type Context struct {
	*Response
	*http.Request
	zerolog.Logger
}

// Error function allow to quickly define an error response
func (c *Context) Error(msg string, code int) error {
	c.error(msg, code)
	return ErrSkip
}

func (c *Context) error(msg string, code int) {
	c.Code = code
	c.Writef(FmtErr, msg)
}

// RemoteHost get the value of the host without the port
func (c *Context) RemoteHost() string {
	host, _, err := net.SplitHostPort(c.RemoteAddr)
	if err != nil {
		return c.RemoteAddr
	}
	return host
}

// Writef creates a text response and write it to the buffer with format
func (c *Context) Writef(format string, a ...interface{}) {
	// according to documentation https://golang.org/pkg/bytes/?m=all#Buffer.Write
	// writing never fails with buffer
	_, _ = fmt.Fprintf(c.Buffer, format, a...)
}

func (c *Context) write() {
	c.Debug().Str("buffer", c.Buffer.String()).Msgf("encoding response")
	if c.Response.w.Header().Get(HeaderContent) == "" {
		c.Response.w.Header().Set(HeaderContent, MimeText+"; charset=utf-8")
	}
	c.Response.w.Header().Set("X-Content-Type-Options", "nosniff")
	c.Response.w.WriteHeader(c.Code)
	if _, err := io.Copy(c.Response.w, c.Buffer); err != nil {
		c.Code = http.StatusInternalServerError
		c.Logger.Error().Err(err).Msg("failed encoding response")
	}
}

// ErrorHandler is the function type we will use to customize error handling
type ErrorHandler func(*Context, error)

// DefaultErrorHandler is the default way of dealing with error in Yubistack.
// It maps error returned by the caller in Yubico text equivalent responses
func DefaultErrorHandler(ctx *Context, err error) {
	switch err {
	case nil, ErrSkip:
		return
	case ykval.ErrNoID, ykval.ErrInvalidID, ykksm.ErrNoOTP, ykval.ErrNoNonce, ykval.ErrInvalidNonce:
		ctx.error(ykval.MissingParameter.String(), http.StatusBadRequest)
	case ykksm.ErrInvalidOTP, ykksm.ErrCorruptOTP, ykval.ErrDelayedOTP, ykauth.ErrInvalidPassword:
		ctx.error(ykval.BadOTP.String(), http.StatusBadRequest)
	case ykval.ErrNoClient:
		ctx.error(ykval.NoSuchClient.String(), http.StatusBadRequest)
	case ykval.ErrInvalidSignature:
		ctx.error(ykval.BadSignature.String(), http.StatusBadRequest)
	case ykval.ErrReplayedOTP:
		ctx.error(ykval.ReplayedOTP.String(), http.StatusBadRequest)
	case ykval.ErrReplayedRequest:
		ctx.error(ykval.ReplayedRequest.String(), http.StatusBadRequest)
	case ykval.ErrNotEnoughAnswers, context.DeadlineExceeded:
		ctx.error(ykval.NotEnoughAnswers.String(), http.StatusInternalServerError)
	case ykauth.ErrNoUser:
		// TODO: decide if we extend Yubico specification or loose information notifying the user.
		//  this case is not handled through Yubico specification. A decision has
		//  to be made regarding this and proper documentation has to be written.
		//  In the meantime relying on this hardcoded string will do the trick.
		ctx.error("NO_USER", http.StatusBadRequest)
	default:
		ctx.error(ykval.BackendError.String(), http.StatusInternalServerError)
	}
	ctx.Logger.Error().Msgf("failed serving %s", ctx.Request.URL.Path)
}

type (
	// Server wraps the serving logic
	Server struct {
		*http.Server
		zerolog.Logger
		ErrorHandler
		middlewares []Middleware
		router      *http.ServeMux
		tlsCertFile string
		tlsKeyFile  string
	}
	// ServerOption is the function type used to customize the Server fields at creation
	ServerOption func(*Server)

	// Middleware is the function type we will use to chain middleware in the application
	Middleware func(HandlerFunc) HandlerFunc
)

// NewServer creates an instance of a server using option parameters to configure.
func NewServer(options ...ServerOption) *Server {
	mux := http.NewServeMux()
	server := &Server{
		Server: &http.Server{
			Addr:         defaultAddr,
			Handler:      mux,
			ReadTimeout:  defaultReadTimeout,
			WriteTimeout: defaultWriteTimeout,
			IdleTimeout:  defaultIdleTimeout,
		},
		Logger:       zerolog.Nop(),
		ErrorHandler: DefaultErrorHandler,
		middlewares:  []Middleware{},
		router:       mux,
	}
	for _, option := range options {
		option(server)
	}
	return server
}

// WithTLS creates a ServerOption setting up TLS options
func WithTLS(certFile, keyFile string) ServerOption {
	return func(server *Server) {
		server.tlsCertFile = certFile
		server.tlsKeyFile = keyFile
	}
}

// Use plugs a middleware in the request handling chain
func (s *Server) Use(middlewares ...Middleware) {
	s.middlewares = append(s.middlewares, middlewares...)
}

// HandleFunc add a handler function to a specific path
func (s *Server) HandleFunc(path string, handle HandlerFunc) {
	wrapped := HandlerFunc(func(ctx *Context) error {
		if err := handle(ctx); err != nil {
			s.ErrorHandler(ctx, err)
		}
		return nil
	})
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		wrapped = s.middlewares[i](wrapped)
	}
	s.router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ctx := &Context{NewResponse(w), r, s.Logger}

		if err := wrapped(ctx); err != nil {
			s.Error().Err(err).Msg("middleware error")
		}
		ctx.write()
	})
}

// Handle add a handler to a specific path
func (s *Server) Handle(path string, handler Handler) { s.HandleFunc(path, handler.Handle) }

// Serve starts a server on the given network and address and route request to handlers
func (s *Server) Serve(network, address string) error {
	if s.tlsCertFile == "" {
		s.Info().Str("addr", address).Msg("serving http")
	} else {
		s.Info().Str("addr", address).Msg("serving https")
	}
	var (
		conn net.Listener
		err  error
	)
	if conn, err = net.Listen(network, address); err != nil {
		return err
	}
	if s.tlsCertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			_ = conn.Close()
			return err
		}
		conn = tls.NewListener(conn, &tls.Config{
			Certificates:             []tls.Certificate{cert},
			CipherSuites:             preferredCiphers,
			PreferServerCipherSuites: true,
			SessionTicketsDisabled:   true,
			CurvePreferences:         preferredCurves,
			MinVersion:               tls.VersionTLS12,
		})
	}
	return s.Server.Serve(conn)
}

// ListenAndServe starts a server on the configured addressed over TCP
func (s *Server) ListenAndServe() error { return s.Serve("tcp", s.Server.Addr) }

// Response wraps the stdlib ResponseWriter interface. It allows to keep
// some states before writing them to the underlying ResponseWriter where
// this information can't be retrieved once pushed. The state is pushed by
// the Context.write() function which is not accessible through the public API.
type Response struct {
	Code   int
	Header http.Header
	*bytes.Buffer
	w http.ResponseWriter
}

// NewResponse creates a new instance of a response with default OK state
func NewResponse(w http.ResponseWriter) *Response {
	return &Response{
		http.StatusOK, w.Header(),
		bytes.NewBuffer(nil), w,
	}
}
