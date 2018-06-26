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

package util

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

func TestWriterFunc(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	writer := WriterFunc(func(p []byte) (int, error) { return buf.Write(p) })
	if _, err := writer.Write([]byte("foo")); err != nil {
		t.Fatalf("failed to write: %q", err)
	}
	if buf.String() != "foo" {
		t.Errorf("WriterFunc.Write(%q) want: %q, got: %q",
			"foo", "foo", buf.String())
	}
}

func TestYubikeyLog(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	logger := zerolog.New(buffer)
	want := `{"level":"info","a":"b","key":{"ctr":1,"use":2},"message":"foo"}
`
	// https://github.com/rs/zerolog/issues/152
	logger.Info().Str("a", "b").
		Object("key", YubikeyLog(yubico.Yubikey{Counter: 1, Use: 2})).
		Msg("foo")
	got := buffer.String()
	if got != want {
		t.Errorf("YubikeyLog() want: %q, got: %q", want, got)
	}
}

func TestYubikeyTsLog(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	logger := zerolog.New(buffer)
	want := `{"level":"info","a":"b","key":{"low":1,"high":2},"message":"foo"}
`
	// https://github.com/rs/zerolog/issues/152
	logger.Info().Str("a", "b").
		Object("key", YubikeyTSLog(yubico.Yubikey{Low: 1, High: 2})).
		Msg("foo")
	got := buffer.String()
	if got != want {
		t.Errorf("YubikeyTsLog() want: %q, got: %q", want, got)
	}
}

func TestTokenLog(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	logger := zerolog.New(buffer)
	token := *internal.TokenAll("", 1, 2, 0, 0)
	want := `{"level":"info","a":"b","key":{"ctr":1,"use":2},"message":"foo"}
`
	// https://github.com/rs/zerolog/issues/152
	logger.Info().Str("a", "b").
		Object("key", TokenLog(token)).Msg("foo")
	got := buffer.String()
	if got != want {
		t.Errorf("TokenLog() want: %q, got: %q", want, got)
	}
}

func TestTokenTsLog(t *testing.T) {
	buffer := bytes.NewBuffer(nil)
	logger := zerolog.New(buffer)
	want := `{"level":"info","a":"b","key":{"low":1,"high":2},"message":"foo"}
`
	// https://github.com/rs/zerolog/issues/152
	logger.Info().Str("a", "b").
		Object("key", TokenTSLog(*internal.Token(1, 2))).
		Msg("foo")
	got := buffer.String()
	if got != want {
		t.Errorf("TokenLog() want: %q, got: %q", want, got)
	}
}
