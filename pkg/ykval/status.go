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
	"errors"
	"fmt"

	"github.com/bookingcom/yubistack/pkg/ykksm"
)

// Status is the binding to a status code
type Status int

const (
	// UnknownStatus is the default base status
	UnknownStatus Status = iota
	// Ok the OTP is valid
	Ok
	// BadOTP the OTP is invalid format
	BadOTP
	// ReplayedOTP the OTP has already been seen by the service.
	ReplayedOTP
	// BadSignature the HMAC signature verification failed.
	BadSignature
	// MissingParameter the request lacks a parameter.
	MissingParameter
	// NoSuchClient the request id does not exist.
	NoSuchClient
	// OperationNotAllowed the request id is not allowed to verify OTPs.
	OperationNotAllowed
	// BackendError unexpected error in our server. Please contact us if you see this error.
	BackendError
	// NotEnoughAnswers server could not get requested number of syncs during before timeout
	NotEnoughAnswers
	// ReplayedRequest server has seen the OTP/Nonce combination before
	ReplayedRequest
)

var (
	//nolint:golint,gochecknoglobals
	statusStrings = []string{
		"UNKNOWN_STATUS",
		"OK",
		"BAD_OTP",
		"REPLAYED_OTP",
		"BAD_SIGNATURE",
		"MISSING_PARAMETER",
		"NO_SUCH_CLIENT",
		"OPERATION_NOT_ALLOWED",
		"BACKEND_ERROR",
		"NOT_ENOUGH_ANSWERS",
		"REPLAYED_REQUEST",
	}

	// ErrNoID is returned when no identifier is provided
	ErrNoID = fmt.Errorf("no ID provided")
	// ErrInvalidID is returned when the identifier is invalid
	ErrInvalidID = fmt.Errorf("invalid ID format")
	// ErrNoNonce is returned when nonce string is not provided
	ErrNoNonce = errors.New("no nonce provided")
	// ErrInvalidNonce is returned when the nonce string format is invalid
	ErrInvalidNonce = errors.New("invalid nonce format")

	// ErrNoClient is returned when no matching client can be found
	ErrNoClient = fmt.Errorf("no matching client")
	// ErrInvalidSignature is returned when the HMAC signature is invalid
	ErrInvalidSignature = fmt.Errorf("invalid signature")

	// ErrDelayedOTP is returned when OTP is out of date
	ErrDelayedOTP = fmt.Errorf("delayed OTP")
	// ErrReplayedOTP is returned when OTP as already been seen
	ErrReplayedOTP = fmt.Errorf("replayed OTP")

	// ErrReplayedRequest is returned when the request as already been seen
	ErrReplayedRequest = fmt.Errorf("replayed request")
	// ErrNotEnoughAnswers is returned when there is not enough answers for consensus
	ErrNotEnoughAnswers = fmt.Errorf("not enough answers")
	// ErrMissingParameter is returned when we miss one or more parameter
	ErrMissingParameter = fmt.Errorf("parameter missing")
	// ErrOperationNotAllowed is returned when something forbidden is requested
	ErrOperationNotAllowed = fmt.Errorf("operation not allowed")
	// ErrBackend is returned when some of the backend return an internal error
	ErrBackend = fmt.Errorf("backend error")
	// ErrUnknown is returned when something unexpected occurs
	ErrUnknown = fmt.Errorf("unknown error")
)

// NewStatus create a Status out of an error string
func NewStatus(str string) Status {
	for i, status := range statusStrings {
		if status == str {
			return Status(i)
		}
	}
	return UnknownStatus
}

// String handle the mapping between a status code and its string representation
func (s Status) String() string {
	i := int(s)
	if i < 0 || len(statusStrings) <= i {
		i = 0
	}
	return statusStrings[i]
}

// Error handle the mapping between a status code and a Go error
func (s Status) Error() error {
	switch s {
	case Ok:
		return nil
	case BadOTP:
		return ykksm.ErrInvalidOTP
	case ReplayedOTP:
		return ErrReplayedOTP
	case BadSignature:
		return ErrInvalidSignature
	case MissingParameter:
		return ErrMissingParameter
	case NoSuchClient:
		return ErrNoClient
	case OperationNotAllowed:
		return ErrOperationNotAllowed
	case BackendError:
		return ErrBackend
	case ReplayedRequest:
		return ErrReplayedRequest
	case NotEnoughAnswers:
		return ErrNotEnoughAnswers
	case UnknownStatus:
		fallthrough
	default:
		return ErrUnknown
	}
}
