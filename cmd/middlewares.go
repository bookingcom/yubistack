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

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/uber/jaeger-client-go"

	"github.com/bookingcom/yubistack/pkg/http"
	"github.com/bookingcom/yubistack/pkg/util"
)

const (
	sizePublic = 12
	sizeReqID  = 8
	// LogKeyTraceID constant extracted value of the trace id field name
	LogKeyTraceID = "pps_trace_id"
	// LogKeySpanID constant extracted value of the span id field name
	LogKeySpanID = "pps_span_id"
	// LogKeyTraceSeq constant extracted value of the span seq field name
	LogKeyTraceSeq = "pps_trace_seq"
	// LogKeyCertKey constant extracted value of the cert key field name
	LogKeyCertKey = "pps_cert_key"
	// LogKeyCertSerial constant extracted value of the cert serial field name
	LogKeyCertSerial = "pps_cert_serial"
	// BaggageKeyCertKey constant extracted value of the cert serial field name
	BaggageKeyCertKey = "pps_cert_key"
	// BaggageKeyCertSerial constant extracted value of the cert serial field name
	BaggageKeyCertSerial = "pps_cert_serial"
)

// LoggingMiddleware logs start and end of incoming requests along the respons code.
func LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// take a context and a handler to wrap, log context information before
	// executing wrapper, pass down the context, wait until execution is done,
	// then log again with updated context information.
	log := func(ctx *http.Context, wrapped http.HandlerFunc) error {
		if ctx.RequestURI == "/health" {
			return wrapped(ctx)
		}
		if id, err := util.Nonce(sizeReqID); err != nil {
			ctx.Logger.Error().Err(err).Msg("failed to generate request id")
		} else {
			ctx.Logger = ctx.Logger.With().Str("id", id).Logger()
		}
		logger := ctx.Logger.With().Str("method", ctx.Method).
			Str("path", ctx.URL.Path).Str("remote", ctx.RemoteHost()).
			Logger()
		logger.Info().Msg("request start")
		err := wrapped(ctx)
		logger.Info().Int("code", ctx.Code).Msg("request end")
		return err
	}
	return func(ctx *http.Context) error { return log(ctx, next) }
}

// TracingMiddleware is responsible for handling the tracing lifecycle.
// Initialize it when request come and closing when request is done.
func TracingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// checks if request has opentracing context and injects the trace context
	// in the logger
	injectOT := func(ctx *http.Context) {
		span := opentracing.SpanFromContext(ctx.Request.Context())
		if nil == span {
			return
		}
		defer span.Finish()
		if sc, ok := span.Context().(jaeger.SpanContext); ok {
			var (
				certKey    = span.BaggageItem(BaggageKeyCertKey)
				certSerial = span.BaggageItem(BaggageKeyCertSerial)
				traceID    = fmt.Sprint(sc.TraceID())
				spanID     = fmt.Sprint(sc.SpanID())
				traceSeq   = fmt.Sprint(span)
			)
			ctx.Logger = ctx.Logger.With().
				Str(LogKeyTraceID, traceID).
				Str(LogKeySpanID, spanID).
				Str(LogKeyTraceSeq, traceSeq).
				Str(LogKeyCertKey, certKey).
				Str(LogKeyCertSerial, certSerial).
				Logger() // TODO - use standardized logging lib keys
		}
	}

	trace := func(ctx *http.Context, wrapped http.HandlerFunc) error {
		// not need for health check
		if ctx.RequestURI == "/health" {
			return wrapped(ctx)
		}
		tracer := opentracing.GlobalTracer()
		spanCtx, err := tracer.Extract(opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(ctx.Request.Header))
		if nil != err {
			// not a problem. New trace context will be generated
			ctx.Logger.Warn().Err(err).Msg("opentracing context not found in the request")
		}
		span := tracer.StartSpan(ctx.Request.URL.Path, ext.RPCServerOption(spanCtx))
		defer span.Finish()

		// Updating the *http.Request with new OpenTracing context
		request := ctx.Request.WithContext(opentracing.ContextWithSpan(ctx.Request.Context(), span))
		ctx.Request = request

		injectOT(ctx)

		// calling the next handler
		return wrapped(ctx)
	}
	return func(ctx *http.Context) error { return trace(ctx, next) }
}

// AuthJSONMiddleware transform text response into JSON response
func AuthJSONMiddleware(matching func(ctx *http.Context) bool) http.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		marshal := func(ctx *http.Context) error {
			status, message := "OK", "authentication succeed"
			otp := ctx.FormValue("otp")
			if len(otp) > sizePublic {
				otp = otp[:sizePublic]
			}

			ctx.Response.Header.Set(http.HeaderContent, http.MimeJSON)
			if _, err := fmt.Fscanf(ctx.Buffer, http.FmtErr, &message); err == nil {
				status = "ERR"
			}
			ctx.Buffer.Reset()
			return json.NewEncoder(ctx.Buffer).Encode(
				map[string]interface{}{
					"status": status, "message": message, "token_id": otp,
					"username": ctx.FormValue("username"),
				},
			)
		}
		return func(ctx *http.Context) error {
			if err := next(ctx); err != nil {
				return err
			}
			if matching(ctx) {
				return marshal(ctx)
			}
			return nil
		}
	}
}
