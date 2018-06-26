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
	"testing"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykksm"
)

//nolint:golint,gochecknoglobals
var statusEntries = []struct {
	status string
	err    error
}{
	{"UNKNOWN_STATUS", ErrUnknown},
	{"OK", nil},
	{"BAD_OTP", ykksm.ErrInvalidOTP},
	{"REPLAYED_OTP", ErrReplayedOTP},
	{"BAD_SIGNATURE", ErrInvalidSignature},
	{"MISSING_PARAMETER", ErrMissingParameter},
	{"NO_SUCH_CLIENT", ErrNoClient},
	{"OPERATION_NOT_ALLOWED", ErrOperationNotAllowed},
	{"BACKEND_ERROR", ErrBackend},
	{"NOT_ENOUGH_ANSWERS", ErrNotEnoughAnswers},
	{"REPLAYED_REQUEST", ErrReplayedRequest},
	{"FOO", ErrUnknown},
}

func TestStatus(t *testing.T) {
	for _, entry := range statusEntries {
		status := NewStatus(entry.status)
		err := status.Error()
		if !internal.ErrEqual(err, entry.err) {
			t.Errorf("Status(%q) => want %s, got %s", entry.status,
				internal.TestError(entry.err), internal.TestError(err))
		}
	}
}

//nolint:golint,gochecknoglobals
var statusCastEntries = []struct {
	status int
	want   string
}{
	{0, "UNKNOWN_STATUS"},
	{1, "OK"},
	{-1, "UNKNOWN_STATUS"},
	{50, "UNKNOWN_STATUS"},
}

func TestStatusCast(t *testing.T) {
	for _, entry := range statusCastEntries {
		got := Status(entry.status).String()
		if entry.want != got {
			t.Errorf("Status(%d) => want %s, got %s",
				entry.status, entry.want, got)
		}
	}
}
