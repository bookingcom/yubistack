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

import (
	"encoding/base64"
	"fmt"

	"github.com/conformal/yubikey"
)

// Client is a structure containing all the information representing a remote client
type Client struct {
	ID      int
	Active  bool
	Created int
	Secret  string
	Email   string
	Notes   string
	OTP     string
}

// Key gets a base64 representation of the client secret
func (c *Client) Key() []byte {
	bytes, err := base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return nil
	}
	return bytes
}

// Yubikey is a structure representing a Yubikey state
type Yubikey struct {
	Active     bool
	Created    int64
	Modified   int64
	PublicName string
	Counter    uint // Number of time the key is plugged
	Use        uint // Number of time the key is tapped
	Low        uint
	High       uint
	Nonce      string
	Notes      string
}

// Clone will creates a new pointer with all fields the same as the original
func (y *Yubikey) Clone() *Yubikey {
	return &Yubikey{
		Active: y.Active, Created: y.Created, Modified: y.Modified,
		PublicName: y.PublicName, Counter: y.Counter, Use: y.Use,
		Low: y.Low, High: y.High, Nonce: y.Nonce, Notes: y.Notes,
	}
}

// Update is setting internal state of Yubikey to new values passed as parameters
func (y *Yubikey) Update(token *Token, nonce string, now int64) *Yubikey {
	y.Counter, y.Use, y.Nonce, y.Modified = uint(token.Counter()), uint(token.Use), nonce, now
	y.Low, y.High = uint(token.Tstpl), uint(token.Tstph)
	return y
}

// String is a string dump of the Yubikey state (not complete).
func (y *Yubikey) String() string {
	return fmt.Sprintf("pub: %s, ctr: %d, use: %d",
		y.PublicName, y.Counter, y.Use)
}

// Token is a structure wrapping a token associated with a readable public part
type Token struct {
	*yubikey.Token
	Public string
}

// String is a string dump of the token (not complete).
func (t *Token) String() string {
	return fmt.Sprintf("pub: %s, ctr: %d, use: %d", t.Public, t.Ctr, t.Use)
}

// User is a structure representing a user of yubistack validating a token
type User struct {
	Name string
	Hash string
}
