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

package internal

import (
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/conformal/yubikey"

	"github.com/bookingcom/yubistack/pkg/yubico"
)

var (
	//nolint:golint,gochecknoglobals
	lvlMap = map[int]string{
		1: "DEBUG",
		2: "INFO",
		3: "WARN",
		4: "ERROR",
		5: "",
	}
	// ErrNoop is here to be used for testing only
	// Purpose is to be propagated up the stack and retrieved/compared later
	// for error propagation check
	ErrNoop = fmt.Errorf("noop")
)

type (
	testToken   yubico.Token
	testYubikey struct{ *yubico.Yubikey }
	testError   struct{ error }
	testRSA     struct{ *rsa.PrivateKey }

	// LogRecords is an array of LogRecord
	LogRecords []LogRecord
	// LogRecord is storing the log arguments to compare them later
	LogRecord struct {
		Level  int
		Format string
		Args   []interface{}
	}
	// DumbYubikeyMapper is an utility structure for test purpose.
	// It allows to customize internal interface behavior at runtime.
	DumbYubikeyMapper struct {
		yubico.YubikeyLoader
		yubico.YubikeyProducer
		yubico.YubikeyUpdater
	}
	// FileCb is a type representing a callback using a file
	// Most probably the wrapping service is responsible for handling the file
	// descriptor lifecycle, the callback is here for user to manipulate the file.
	FileCb func(*os.File) error
)

// String dump the current token as a string
func (tt testToken) String() string {
	return fmt.Sprintf("Token(%s){c: %d, u: %d, h: %d, l: %d}", tt.Public,
		tt.Counter(), tt.Use, tt.Tstph, tt.Tstpl)
}

// TestToken creates a token for testing purpose out of a yubico.Token
func TestToken(token *yubico.Token) testToken { //nolint:golint
	if token == nil {
		return testToken(*Token(0, 0))
	}
	return testToken(*token)
}

// TestYubikey creates a yubikey for testing purpose out of a yubico.Yubikey
func TestYubikey(ykey *yubico.Yubikey) testYubikey { //nolint:golint
	return testYubikey{ykey}
}

// String dump the current yubikey as a string
func (ty testYubikey) String() string {
	if ty.Yubikey == nil {
		return "Yubikey{nil}"
	}
	return "Yubikey{" + ty.Yubikey.PublicName + "}"
}

// TestError creates an error for testing purpose out of a regular error interface
func TestError(err error) testError { //nolint:golint
	return testError{err}
}

// Error satisfy the error interface
func (te testError) Error() string {
	return te.String()
}

// String dump the current error as a string
func (te testError) String() string {
	if te.error == nil {
		return "Error{nil}"
	}
	return "Error{" + te.error.Error() + "}"
}

// TestRSA creates a rsa private key for testing purpose out of a rsa.PrivateKey pointer
func TestRSA(key *rsa.PrivateKey) testRSA { //nolint:golint
	return testRSA{key}
}

// String dump the current rsa private key as a string
func (tr testRSA) String() string {
	if tr.PrivateKey == nil {
		return "PrivateKey{nil}"
	}
	return "PrivateKey{" + tr.PrivateKey.D.String()[:10] + "...}"
}

// Token is an util function to create a yubico.Token with only low and high markers
func Token(low uint16, high uint8) *yubico.Token {
	return &yubico.Token{Token: &yubikey.Token{Tstph: high, Tstpl: low}}
}

// TokenAll is an util function to create a yubico.Token with all fields set up
func TokenAll(name string, ctr, use, high, low uint) *yubico.Token {
	return &yubico.Token{
		Public: name, Token: &yubikey.Token{
			Ctr: uint16(ctr), Use: uint8(use), Tstph: uint8(high), Tstpl: uint16(low),
		},
	}
}

// Key is an util function to create a yubico.Yubikey with all fields set up
func Key(name string, modified int64, low, high uint) *yubico.Yubikey {
	return &yubico.Yubikey{PublicName: name, Modified: modified, Low: low, High: high}
}

// ErrEqual compare two errors, it is safe to use with nil values and will compare
// the string representation
func ErrEqual(err1, err2 error) bool {
	return (err1 == nil && err2 == nil) ||
		(err1 != nil && err2 != nil && err1.Error() == err2.Error())
}

// YubikeyEqual compare two yubikeys, it is safe to use with nil values.
// It only compares the public name attribute (sufficient for tests)
func YubikeyEqual(ykey1, ykey2 *yubico.Yubikey) bool {
	return (ykey1 == nil && ykey2 == nil) ||
		(ykey1 != nil && ykey2 != nil && ykey1.PublicName == ykey2.PublicName)
}

// TokenEqual compare two tokens, it is safe to use with nil values.
func TokenEqual(token1, token2 *yubico.Token) bool {
	return (token1 == nil && token2 == nil) ||
		(token1 != nil && token2 != nil && token1.Public == token2.Public &&
			token1.Ctr == token2.Ctr && token1.Use == token2.Use &&
			token1.Tstph == token2.Tstph && token1.Tstpl == token2.Tstpl)
}

// IntEqual compare two big.Int, it is safe to use with nil values.
// Comparison is done against the string representation of the arguments.
func IntEqual(int1, int2 *big.Int) bool {
	return (int1 == nil && int2 == nil) ||
		(int1 != nil && int2 != nil && int1.String() == int2.String())
}

// RSAEqual compare two RSA private keys, it is safe to use with nil values.
// Comparison is done against the string representation of the internal big.Int.
func RSAEqual(key1, key2 *rsa.PrivateKey) bool {
	return (key1 == nil && key2 == nil) ||
		(key1 != nil && key2 != nil && IntEqual(key1.D, key2.D))
}

// Log is a wrapper to save logs in a cache for later comparison
// nolint:goprintffuncname
func (lg *LogRecords) Log(level int, format string, a ...interface{}) {
	*lg = append(*lg, LogRecord{level, format, a})
}

// String is a dump of an array of LogRecord
func (lg *LogRecords) String() string {
	var records []string
	for _, record := range *lg {
		records = append(records, record.String())
	}
	return "LogRecords[" + strings.Join(records, ", ") + "]"
}

// Reset reinitialize the internal cache
func (lg *LogRecords) Reset() { *lg = []LogRecord{} }

// String is a dump of a LogRecord
func (lg LogRecord) String() string {
	return fmt.Sprintf(lvlMap[lg.Level]+": "+lg.Format, lg.Args...)
}

// LogRecordsEqual compare two LogRecord arrays, it is safe to use with nil values.
// Comparison is done against the level and format (if arguments differs it will still return true).
func LogRecordsEqual(lr1, lr2 *LogRecords) bool {
	if len(*lr1) != len(*lr2) {
		return false
	}
	for i, r1 := range *lr1 {
		r2 := (*lr2)[i]
		// we don't test against the arguments yet, may need to be introduced later
		if r1.Level != r2.Level || r1.Format != r2.Format {
			return false
		}
	}
	return true
}

// NewDumbYubikeyMapper creates a DumbYubikeyMapper with sensible defaults implementations
func NewDumbYubikeyMapper() *DumbYubikeyMapper {
	return &DumbYubikeyMapper{
		yubico.YubikeyLoaderFunc(func(string) (*yubico.Yubikey, error) {
			return &yubico.Yubikey{Active: true}, nil
		}),
		yubico.YubikeyProducerFunc(func(*yubico.Token, string) (*yubico.Yubikey, error) {
			return &yubico.Yubikey{Active: true}, nil
		}),
		yubico.YubikeyUpdaterFunc(func(*yubico.Yubikey) error { return nil }),
	}
}

// YubikeyLoad implement the load interface and return the internal implementation
func (dym DumbYubikeyMapper) YubikeyLoad(name string) (*yubico.Yubikey, error) {
	if dym.YubikeyLoader != nil {
		return dym.YubikeyLoader.YubikeyLoad(name)
	}
	return nil, fmt.Errorf("dumb loader")
}

// YubikeyProduce implement the load interface and return the internal implementation
func (dym DumbYubikeyMapper) YubikeyProduce(
	token *yubico.Token, nonce string,
) (*yubico.Yubikey, error) {
	if dym.YubikeyProducer != nil {
		return dym.YubikeyProducer.YubikeyProduce(token, nonce)
	}
	return nil, fmt.Errorf("dumb producer")
}

// YubikeyUpdate implement the update interface and return the internal implementation
func (dym DumbYubikeyMapper) YubikeyUpdate(yubikey *yubico.Yubikey) error {
	if dym.YubikeyUpdater != nil {
		return dym.YubikeyUpdater.YubikeyUpdate(yubikey)
	}
	return fmt.Errorf("dumb updater")
}

// ReadAll is a wrapper around ioutil.ReadAll and abort on error
func ReadAll(t *testing.T, r io.Reader) string {
	t.Helper()
	content, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read from buffer")
	}
	return string(content)
}

// StrSliceEqual compare two slices of strings, it is safe to use with nil values.
func StrSliceEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

// TempFile wraps the ioutil.TempFile, handling the lifecycle of the file
// and removing it when callback has been executed
func TempFile(t *testing.T, cb func(*os.File) error) error {
	t.Helper()
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("failed to create temp file for test: %q", err)
	}
	defer func() {
		if _, err := os.Stat(file.Name()); os.IsNotExist(err) {
			return
		}
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("failed to teardown test: %q", err)
		}
	}()
	return cb(file)
}

// TempFileName wraps the ioutil.TempFile, handling the lifecycle of the file
// and removing it when callback has been executed. It only pass the name and
// not the file descriptor.
func TempFileName(t *testing.T, cb func(string) error) error {
	t.Helper()
	err := TempFile(t, func(file *os.File) error {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("unexpected error: %q", err)
		}
		return cb(file.Name())
	})
	return err
}
