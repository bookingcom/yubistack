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

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/conformal/yubikey"
	_ "github.com/go-sql-driver/mysql"
)

const (
	insertYKVALClient  = `INSERT INTO clients (id, active, created, secret) VALUES(?, '1', 1383728711, '')`
	insertYKVALYubikey = `INSERT INTO yubikeys (active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high)
VALUES('1', ?, ?, ?, 0, 0, 0, 0)`

	// hash is generated with following command: openssl passwd -5 <(echo foo)
	insertYKAuthUsers = `INSERT INTO users (id, name, auth)
VALUES(?, ?, '$5$0THN5OEWkGvvUfAf$FdlC6utzlDHAIsiAuZ6.t8c7uIZKwIJXlPIWbJr0Mk2')`
	insertYKAuthYubikeys      = `INSERT INTO yubikeys (id, prefix, enabled) VALUES(?, ?, '1')`
	insertYkAuthUsersYubikeys = `INSERT INTO user_yubikeys (user_id, yubikey_id) VALUES(?, ?)`
	insertYKKSM               = `INSERT INTO yubikeys (publicname,internalname,aeskey,serialnr,created,lockcode,creator)
VALUES(?,?,?,0,0,'','')`
)

//nolint:golint,gochecknoglobals
var (
	numberKeys    = 10
	numberClients = 1
	numberWorkers = 10

	startingPort = 3000
)

type (
	// Yubikey structure is a convenient structure storing information of a Yubikey
	Yubikey struct {
		id       int
		public   []byte
		internal []byte
		aes      []byte
	}
	// Exec is a structure storing the arguments of a sql exec statement
	Exec struct {
		*sql.DB
		Query string
		Args  []interface{}
	}
)

// nolint:gochecknoinits
func init() {
	flag.IntVar(&numberKeys, "k", numberKeys,
		"number of virtual key to create.")
	flag.IntVar(&startingPort, "s", startingPort,
		"the starting port from which the script will iterate clients to forward to.")
	flag.IntVar(&numberClients, "c", numberClients,
		"number of client to iterate and initialize.")
	flag.IntVar(&numberWorkers, "w", numberWorkers,
		"number of workers used for database insertion.")
	flag.Parse()
}

// NewYubikey creates a Yubikey structure with proper default fields initialized
func NewYubikey(options ...func(*Yubikey)) *Yubikey {
	y := &Yubikey{
		public:   make([]byte, yubikey.UidSize),
		internal: make([]byte, yubikey.UidSize),
		aes:      make([]byte, yubikey.KeySize),
	}
	for _, option := range options {
		option(y)
	}

	return y
}

// Public returns the hexadecimal encoding of the public part of the Yubikey
func (y *Yubikey) Public() string {
	return string(yubikey.ModHexEncode(y.public))
}

// Internal returns the hexadecimal encoding of the internal key of the Yubikey
func (y *Yubikey) Internal() string {
	return hex.EncodeToString(y.internal)
}

// UID returns the UID of the yubikey using the internal key
func (y *Yubikey) UID() yubikey.Uid {
	return yubikey.NewUid(y.internal)
}

// AES returns the hexadecimal representation of the yubikey AES key
func (y *Yubikey) AES() string {
	return hex.EncodeToString(y.aes)
}

// Key returns the yubikey key using the yubikey AES key
func (y *Yubikey) Key() yubikey.Key {
	return yubikey.NewKey(y.aes)
}

func connect(endpoint, name string) string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", "root", "some_password", endpoint, name)
}

func generator(count, workers int) map[string]*Yubikey {
	keys := make(map[string]*Yubikey, count)
	out := make(chan *Yubikey, 10)
	done := make(chan struct{})

	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					out <- NewYubikey(func(y *Yubikey) {
						if _, err := rand.Read(y.aes); err != nil {
							log.Printf("failed to generate AES key")
							return
						}
						if _, err := rand.Read(y.public); err != nil {
							log.Printf("failed to generate public name")
							return
						}
						if _, err := rand.Read(y.internal); err != nil {
							log.Printf("failed to generate internal name")
							return
						}
					})
				}
			}
		}()
	}
	for key := range out {
		if count == 0 {
			close(done) // avoid leaking
			break
		}
		if _, ok := keys[key.Public()]; !ok { // avoid duplicates
			key.id = count
			keys[key.Public()] = key
			count--
		}
	}
	return keys
}

func exec(in <-chan *Exec, wg *sync.WaitGroup) {
	for msg := range in {
		if _, err := msg.Exec(msg.Query, msg.Args...); err != nil {
			log.Fatalf(
				"failed to execute: %q, with: %+v, got: %q",
				msg.Query, msg.Args, err,
			)
		}
		wg.Done()
	}
}

func main() {
	var (
		db      *sql.DB
		err     error
		conn    string
		ykksms  = make([]*sql.DB, numberClients)
		ykvals  = make([]*sql.DB, numberClients)
		ykauths = make([]*sql.DB, numberClients)
		wg      = sync.WaitGroup{}
		in      = make(chan *Exec, 100)
		// this allow a sufficient tolerance
		now = time.Now().Add(-24 * time.Hour).Unix()
	)
	for i := 0; i < numberWorkers; i++ { // start workers
		go exec(in, &wg)
	}
	for i := 0; i < numberClients; i++ {
		// YKKSM connection
		conn = connect("localhost:"+strconv.Itoa(startingPort+i), "ykksm")
		db, err = sql.Open("mysql", conn)
		if err != nil {
			log.Fatalf("failed to connect to port: %d, err: %q", startingPort+i, err)
		}
		if _, err = db.Exec("DELETE FROM yubikeys"); err != nil {
			log.Fatalf("failed to clean up ksm database: %q", err)
		}
		ykksms[i] = db

		// YKVAL connection
		conn = connect("localhost:"+strconv.Itoa(startingPort+i), "ykval")
		db, err = sql.Open("mysql", conn)
		if err != nil {
			log.Fatalf("failed to connect to port: %d, err: %q", startingPort+i, err)
		}
		if _, err = db.Exec("DELETE FROM clients"); err != nil {
			log.Fatalf("failed to clean up ykval database: %q", err)
		}
		if _, err = db.Exec("DELETE FROM yubikeys"); err != nil {
			log.Fatalf("failed to clean up ykval database: %q", err)
		}
		ykvals[i] = db

		// YKAuth connection
		conn = connect("localhost:"+strconv.Itoa(startingPort+i), "yubiauth")
		db, err = sql.Open("mysql", conn)
		if err != nil {
			log.Fatalf("failed to connect to port: %d, err: %q", startingPort+i, err)
		}
		if _, err = db.Exec("DELETE FROM user_yubikeys"); err != nil {
			log.Fatalf("failed to clean up ykauth database: %q", err)
		}
		if _, err = db.Exec("DELETE FROM users"); err != nil {
			log.Fatalf("failed to clean up ykauth database: %q", err)
		}
		if _, err = db.Exec("DELETE FROM yubikeys"); err != nil {
			log.Fatalf("failed to clean up ykauth database: %q", err)
		}
		ykauths[i] = db
	}
	i := 0
	for name, key := range generator(numberKeys, numberWorkers) {
		log.Printf("populating: %q", name)
		for _, ykksm := range ykksms {
			wg.Add(1)
			in <- &Exec{
				ykksm, insertYKKSM,
				[]interface{}{key.Public(), key.Internal(), key.AES()},
			}
		}
		for _, ykval := range ykvals {
			wg.Add(2)
			in <- &Exec{ykval, insertYKVALClient, []interface{}{key.id}}
			in <- &Exec{ykval, insertYKVALYubikey, []interface{}{now, now, key.Public()}}
		}
		for _, ykauth := range ykauths {
			wg.Add(3)
			in <- &Exec{ykauth, insertYKAuthYubikeys, []interface{}{i + 1, key.Public()}}
			in <- &Exec{ykauth, insertYKAuthUsers, []interface{}{i + 1, key.Public()}}
			in <- &Exec{ykauth, insertYkAuthUsersYubikeys, []interface{}{i + 1, i + 1}}
		}
		i++
		fmt.Printf("public=%s internal=%s aes=%s\n",
			key.Public(), key.Internal(), key.AES())
	}
	wg.Wait()
}
