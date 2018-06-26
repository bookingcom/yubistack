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
	"context"
	"net/http/httptest"
	"testing"

	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/http"
)

func TestTracingMiddleWare(t *testing.T) {
	capture := new(ctxCapturer)
	handler := TracingMiddleware(capture.Handle)

	// test health request
	ctx := &http.Context{
		Response: nil,
		Request:  httptest.NewRequest("GET", "/health", nil),
		Logger:   zerolog.Logger{},
	}
	if err := handler(ctx); nil != err {
		t.Error(errors.Wrap(err, "shouldn't return error"))
	}
	if span := opentracing.SpanFromContext(capture.context); nil != span {
		t.Error("health request shouldn't be updated with trace-context")
	}

	// test normal request
	ctx = &http.Context{
		Response: nil,
		Request:  httptest.NewRequest("GET", "/test-url", nil),
		Logger:   zerolog.Logger{},
	}
	if err := handler(ctx); nil != err {
		t.Error(errors.Wrap(err, "shouldn't return error"))
	}
	if span := opentracing.SpanFromContext(capture.context); nil == span {
		t.Error("request context should be updated with opentracing context")
	}
}

type ctxCapturer struct {
	context context.Context
}

func (c *ctxCapturer) Handle(ctx *http.Context) error {
	c.context = ctx.Request.Context()
	return nil
}
