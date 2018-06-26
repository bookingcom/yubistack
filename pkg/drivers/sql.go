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

package drivers

import (
	"database/sql"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

const (
	getAESKey  = `SELECT aeskey, internalname FROM yubikeys WHERE publicname = ? AND active = 1`
	getYubikey = `SELECT active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes
FROM yubikeys WHERE yk_publicname = ?`
	insertYubikey = `INSERT INTO yubikeys(active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	getClient     = `SELECT id, active, created, secret, email,  notes, otp FROM clients WHERE id = ?`
	updateYubikey = `UPDATE yubikeys SET yk_counter=?, yk_use=?, yk_low=?, yk_high=?, nonce=?, modified=?
WHERE yk_publicname=? AND (yk_counter <= ? OR (yk_counter = ? AND yk_use < ?))`
	getUser = `SELECT auth FROM user_yubikeys uy, users u, yubikeys y
WHERE uy.user_id = u.id AND uy.yubikey_id = y.id AND u.name = ? AND y.prefix = ? AND y.enabled = 1`
)

var (
	// ErrDB is simple error to propagate up the call stack
	ErrDB = errors.New("database error")
)

type (
	// YKKSM is a wrapper around a database client and a logger
	// It handles the communication with the YKKSM database
	YKKSM struct {
		zerolog.Logger
		*sql.DB
	}
	// YKVal is a wrapper around a database client and a logger
	// It handles the communication with the YKVal database
	YKVal struct {
		zerolog.Logger
		*sql.DB
	}
	// YKAuth is a wrapper around a database client and a logger
	// It handles the communication with the YKAuth database
	YKAuth struct {
		zerolog.Logger
		*sql.DB
	}
)

// NewYKVal creates a new YKVal structure with sensible defaults
func NewYKVal(db *sql.DB, options ...func(*YKVal)) *YKVal {
	ykval := &YKVal{DB: db, Logger: zerolog.Nop()}
	for _, option := range options {
		option(ykval)
	}
	return ykval
}

// YubikeyProduce implements the YubikeyProducer interface.
// It  creates a new yubikey, save it and then return it to the caller
func (y *YKVal) YubikeyProduce(token *yubico.Token, _ string) (*yubico.Yubikey, error) {
	logger := y.With().Str("public", token.Public).Str("db", "ykval").Logger()
	logger.Debug().Msg("creating yubikey")
	now := time.Now().Unix()
	ykey := &yubico.Yubikey{
		PublicName: token.Public, Active: true, Created: now, Modified: now,
		High: uint(token.Tstph), Low: uint(token.Tstpl),
	}
	stmt, err := y.Prepare(insertYubikey)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return nil, err
	}
	defer func() { _ = stmt.Close() }()
	_, err = stmt.Exec(
		ykey.Active, ykey.Created, ykey.Modified, ykey.PublicName,
		ykey.Counter, ykey.Use, ykey.Low, ykey.High, ykey.Nonce, ykey.Notes,
	)
	return ykey, err
}

// YubikeyUpdate implements the YubikeyUpdater interface.
// It pushes the new state to the underlying database.
func (y *YKVal) YubikeyUpdate(yubikey *yubico.Yubikey) error {
	logger := y.With().Str("public", yubikey.PublicName).Str("db", "ykval").Logger()
	logger.Debug().Msg("updating yubikey")
	stmt, err := y.Prepare(updateYubikey)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return err
	}
	defer func() { _ = stmt.Close() }()
	if yubikey.Modified == 0 { // ensure that modified is always set
		yubikey.Modified = time.Now().Unix()
	}
	_, err = stmt.Exec(
		yubikey.Counter, yubikey.Use, yubikey.Low, yubikey.High, yubikey.Nonce,
		yubikey.Modified, yubikey.PublicName, yubikey.Counter, yubikey.Counter,
		yubikey.Use,
	)
	return err
}

// YubikeyLoad implements the YubikeyLoader interface.
// It retrieves yubikey from the underlying database and returns it.
func (y *YKVal) YubikeyLoad(name string) (*yubico.Yubikey, error) {
	logger := y.With().Str("public", name).Str("db", "ykval").Logger()
	logger.Debug().Msg("loading yubikey")
	key := &yubico.Yubikey{}

	stmt, err := y.Prepare(getYubikey)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return nil, err
	}
	defer func() { _ = stmt.Close() }()
	err = stmt.QueryRow(name).Scan(
		&key.Active, &key.Created, &key.Modified, &key.PublicName, &key.Counter,
		&key.Use, &key.Low, &key.High, &key.Nonce, &key.Notes,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			err = ykksm.ErrNoYubikey
		} else {
			logger.Error().Err(err).Msg("query execution failed")
			err = ErrDB
		}
	}
	return key, err
}

// LoadClient implements the ClientLoader interface.
// It retrieves a client by its id from the database and returns it.
func (y *YKVal) LoadClient(id uint64) (*yubico.Client, error) {
	logger := y.With().Uint64("client", id).Str("db", "ykval").Logger()
	logger.Debug().Msg("loading client")
	client := &yubico.Client{}
	stmt, err := y.Prepare(getClient)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return nil, ErrDB
	}
	defer func() { _ = stmt.Close() }()

	email, notes := sql.NullString{}, sql.NullString{}
	err = stmt.QueryRow(int(id)).Scan(
		&client.ID, &client.Active, &client.Created, &client.Secret,
		&email, &notes, &client.OTP,
	)
	client.Email, client.Notes = email.String, notes.String
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error().Msgf("unknown client")
			err = ykval.ErrNoClient
		} else {
			logger.Error().Err(err).Msg("query execution failed")
			err = ErrDB
		}
	}
	return client, err
}

// NewYKKSM creates a new YKKSM structure with sensible defaults
func NewYKKSM(db *sql.DB, options ...func(*YKKSM)) *YKKSM {
	ykksm := &YKKSM{DB: db, Logger: zerolog.Nop()}
	for _, option := range options {
		option(ykksm)
	}
	return ykksm
}

// Retrieve implements the Retriever interface.
// It retrieves the key and name by its pubid and returns it.
func (y *YKKSM) Retrieve(pubid []byte) (key []byte, name string, err error) {
	logger := y.With().Bytes("public", pubid).Str("db", "ykksm").Logger()
	logger.Debug().Msgf("loading yubikey")
	stmt, err := y.Prepare(getAESKey)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return key, name, ErrDB
	}
	defer func() { _ = stmt.Close() }()

	if err = stmt.QueryRow(string(pubid)).Scan(&key, &name); err != nil {
		if err == sql.ErrNoRows {
			logger.Error().Msgf("unknown yubikey")
			err = ykksm.ErrNoYubikey
		} else {
			logger.Error().Err(err).Msg("query execution failed")
			err = ErrDB
		}
	}
	return
}

// NewYKAuth creates a new YKAuth structure with sensible defaults.
func NewYKAuth(db *sql.DB, options ...func(*YKAuth)) *YKAuth {
	ykauth := &YKAuth{DB: db, Logger: zerolog.Nop()}
	for _, option := range options {
		option(ykauth)
	}
	return ykauth
}

// LoadUser is responsible from loading a user by its name from the underlying database.
func (y *YKAuth) LoadUser(name, public string) (*yubico.User, error) {
	logger := y.With().Str("public", public).Str("name", name).
		Str("db", "ykauth").Logger()
	logger.Debug().Msgf("loading user")
	hash := sql.NullString{}
	stmt, err := y.Prepare(getUser)
	if err != nil {
		logger.Error().Err(err).Msg("query preparation failed")
		return nil, ErrDB
	}
	defer func() { _ = stmt.Close() }()
	if err = stmt.QueryRow(name, public).Scan(&hash); err != nil {
		if err == sql.ErrNoRows {
			logger.Error().Msgf("unknown user")
			err = ykauth.ErrNoUser
		} else {
			logger.Error().Err(err).Msgf("query execution failed")
			err = ErrDB
		}
	}
	user := &yubico.User{Name: name, Hash: hash.String}
	return user, err
}
