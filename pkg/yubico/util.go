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

package yubico

type (
	// ClientLoaderFunc is a wrapper for a function to implement the ClientLoader interface
	ClientLoaderFunc func(uint64) (*Client, error)
	// ClientLoader is an interface abstracting a loading of a client.
	// It will most likely been loaded from a database, but we want to abstract that away.
	ClientLoader interface {
		LoadClient(id uint64) (*Client, error)
	}
)

// LoadClient wraps a function to implement ClientLoader interface
func (clf ClientLoaderFunc) LoadClient(id uint64) (*Client, error) { return clf(id) }

type (
	// UserLoader is an interface abstracting a loading of a user from store.
	// It will most likely been loaded from a database, but we want to abstract that away.
	UserLoader interface {
		LoadUser(name, public string) (*User, error)
	}
	// UserLoaderFunc is a wrapper for a function to implement the UserLoader interface
	UserLoaderFunc func(name, public string) (*User, error)
)

// LoadUser wraps a function to implement UserLoader interface
func (ulf UserLoaderFunc) LoadUser(name, public string) (*User, error) { return ulf(name, public) }

type (
	// YubikeyLoaderFunc is a wrapper for a function to implement the YubikeyLoader interface
	YubikeyLoaderFunc func(name string) (*Yubikey, error)
	// YubikeyLoader is an interface abstracting a loading of a Yubikey state.
	// It will most likely been loaded from a database, but we want to abstract that away.
	YubikeyLoader interface {
		YubikeyLoad(name string) (*Yubikey, error)
	}
)

// YubikeyLoad wraps a function to implement YubikeyLoader interface
func (ylf YubikeyLoaderFunc) YubikeyLoad(name string) (*Yubikey, error) { return ylf(name) }

type (
	// YubikeyProducerFunc is a wrapper for a function to implement the YubikeyProducer interface
	YubikeyProducerFunc func(token *Token, nonce string) (*Yubikey, error)
	// YubikeyProducer is an interface abstracting the creation of a Yubikey.
	// It will most likely been saved to a database, but we want to abstract that away.
	YubikeyProducer interface {
		YubikeyProduce(token *Token, nonce string) (*Yubikey, error)
	}
)

// YubikeyProduce wraps a function to implement ClientLoader interface
func (ypf YubikeyProducerFunc) YubikeyProduce(token *Token, nonce string) (*Yubikey, error) {
	return ypf(token, nonce)
}

type (
	// YubikeyUpdaterFunc is a wrapper for a function to implement the YubikeyUpdater interface
	YubikeyUpdaterFunc func(*Yubikey) error

	// YubikeyUpdater is an interface abstracting the update of a Yubikey state.
	// It will most likely been saved to a database, but we want to abstract that away.
	YubikeyUpdater interface {
		YubikeyUpdate(*Yubikey) error
	}
)

// YubikeyUpdate wraps a function to implement YubikeyUpdater interface
func (yuf YubikeyUpdaterFunc) YubikeyUpdate(key *Yubikey) error { return yuf(key) }

// YubikeyDBMapper is an interface aggregator for Yubikey database interactions.
type YubikeyDBMapper interface {
	YubikeyLoader
	YubikeyUpdater
	YubikeyProducer
}
