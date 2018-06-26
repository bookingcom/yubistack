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

package ykauth

type (
	// AuthentifierFunc is a wrapper for a function to implement the Authentifier interface
	AuthentifierFunc func(name, otp, password string) error
	// Authentifier is an interface abstracting the Authenticate process
	Authentifier interface {
		Authenticate(name, password, otp string) error
	}
)

// Authenticate wraps a function to implement Authentifier interface
func (af AuthentifierFunc) Authenticate(name, otp, password string) error {
	return af(name, otp, password)
}

type (
	// AuthorizerFunc is a wrapper for a function to implement the Authorizer interface
	AuthorizerFunc func(name, otp string) error
	// Authorizer is an interface abstracting the Authorizer process
	Authorizer interface {
		Authorize(name, otp string) error
	}
)

// Authorize wraps a function to implement Authorizer interface
func (af AuthorizerFunc) Authorize(name, otp string) error {
	return af(name, otp)
}

// VerifyPassword checks a password against its potential hash
func VerifyPassword(password, hash string) bool {
	return crypter.Verify(hash, []byte(password)) == nil
}
