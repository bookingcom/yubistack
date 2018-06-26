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
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/conformal/yubikey"
)

const (
	authURL   = "http://%s/wsapi/authenticate?%s"
	inFmt     = "public=%s internal=%s aes=%s\n"
	outFmt    = "key: %s, request: %d, elapsed: %s"
	maxUint16 = ^uint16(0)
	password  = "foo" // from populate.go -> insertYKAuthUsers
)

//nolint:golint,gochecknoglobals
var (
	numberOTPs    = 10
	clientIPs     = "localhost:8080"
	clientTimeout = 10
	clientWait    = 1000
	maxUint16Big  = big.NewInt(int64(maxUint16))
)

type (
	// VirtualKey is a structure mocking a yubikey for testing purpose
	VirtualKey struct {
		Public   string
		internal yubikey.Uid
		key      yubikey.Key
	}
)

// nolint:gochecknoinits
func init() {
	flag.IntVar(&numberOTPs, "o", numberOTPs,
		"number of OTPs to emulate.")
	flag.StringVar(&clientIPs, "c", clientIPs,
		"clients endpoints to reach for benchmarking.")
	flag.IntVar(&clientTimeout, "t", clientTimeout,
		"http client timeout.")
	flag.IntVar(&clientWait, "w", clientWait,
		"time to wait between two request for the same yubikey in millisecond.")
	flag.Parse()
}

// SetInternal get an hexadecimal internal id and set the internal yubikey with it.
func (k *VirtualKey) SetInternal(internal string) error {
	buf, err := hex.DecodeString(internal)
	if err != nil {
		return err
	}
	k.internal = yubikey.NewUid(buf)
	return nil
}

// SetKey get an hexadecimal key and set the internal yubikey with it.
func (k *VirtualKey) SetKey(key string) (err error) {
	buf, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	k.key = yubikey.NewKey(buf)
	return nil
}

// NewOTP generate a token using the virtual key and the parameters given.
func (k *VirtualKey) NewOTP(ctr uint16, use uint8, tstpl uint16, tstph uint8) string {
	token := yubikey.NewToken(k.internal, ctr, tstpl, tstph, use, rnd()).Generate(k.key)
	return k.Public + string(token.Bytes())
}

func rnd() uint16 {
	i, err := rand.Int(rand.Reader, maxUint16Big)
	if err != nil {
		panic("failed to generate random uint16")
	}
	return uint16(i.Int64())
}

func robin(values []string) func() string {
	i := 0
	l := len(values)
	return func() string {
		defer func() { i++ }()
		return values[i%l]
	}
}

func duration(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func main() {
	keys := make([]*VirtualKey, 0)
	wg := sync.WaitGroup{}
	generator := robin(strings.Split(clientIPs, ","))
	errors := 0
	client := http.Client{Timeout: time.Duration(clientTimeout) * time.Second}

	for {
		public, internal, aes := "", "", ""
		if _, err := fmt.Scanf(inFmt, &public, &internal, &aes); err != nil {
			if err == io.ErrUnexpectedEOF {
				break
			}
			log.Fatalf("failed to scan input: %q", err)
		}
		key := &VirtualKey{Public: public}
		if err := key.SetInternal(internal); err != nil {
			log.Fatalf("failed to scan input: %q", err)
		}
		if err := key.SetKey(aes); err != nil {
			log.Fatalf("failed to scan input: %q", err)
		}
		keys = append(keys, key)
	}
	log.Printf("%d keys scanned", len(keys))
	wg.Add(len(keys))
	for _, key := range keys {
		go func(key *VirtualKey) {
			for i := 0; i < numberOTPs; i++ {
				err, resp := io.EOF, &http.Response{}
				values := url.Values{
					// five minutes
					"otp": {key.NewOTP(uint16(i+1), uint8(i+1),
						// one day yubikey clicking 24*60*60*8 = 691200
						// max uint16 = 65535
						// 691200  = 10 *  65535 + 35850
						uint16(i*(clientWait*8/1000)+35850), 10)},
					"username": {key.Public},
					"password": {password},
				}
				elapsed := duration(func() {
					// nolint:bodyclose
					resp, err = client.Get(fmt.Sprintf(authURL, generator(), values.Encode()))
				})
				// nolint:gocritic
				if err != nil {
					log.Printf("failed to send authentication: %q", err)
					errors++
				} else if resp.StatusCode != http.StatusOK {
					bytes, _ := ioutil.ReadAll(resp.Body)
					log.Printf("failed authentication, status: %q, body: %q",
						resp.Status, string(bytes))
					errors++
				} else {
					log.Printf(outFmt, key.Public, i, elapsed)
				}
				time.Sleep(time.Duration(clientWait) * time.Millisecond)
			}
			wg.Done()
		}(key)
	}
	wg.Wait()
	fmt.Printf("total number of request: %d, total number of errors: %d\n",
		len(keys)*numberOTPs, errors)
}
