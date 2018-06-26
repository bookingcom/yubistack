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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	authURL = "http://%s/wsapi/authenticate"
)

//nolint:golint,gochecknoglobals
var (
	server   = "localhost"
	timeout  = 10
	password = false
)

// nolint:gochecknoinits
func init() {
	flag.BoolVar(&password, "p", password, "authenticate with password, will start a prompt.")
	flag.StringVar(&server, "s", server, "yubistack server to reach.")
	flag.IntVar(&timeout, "t", timeout, "http client timeout in second.")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [flags] <username> <otp>:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
}

func main() {
	if flag.NArg() != 2 {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(),
			"You need to specify a <username> and <otp>\n")
		flag.Usage()
		os.Exit(1)
	}
	values := url.Values{"username": {flag.Arg(0)}, "otp": {flag.Arg(1)}}
	if password {
		_, _ = fmt.Fprintf(os.Stdout, "password: ")
		bytes, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			_, _ = fmt.Fprintf(flag.CommandLine.Output(),
				"Failed to retrieve password from command line: %q\n", err)
			os.Exit(1)
		}
		values.Add("password", string(bytes))
	}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.PostForm(fmt.Sprintf(authURL, server), values)
	if err != nil {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(),
			"Unexpected error when contacting %q: %q\n", server, err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(),
			"Unexpected status code: %q\n", resp.Status)
		if body, err := ioutil.ReadAll(resp.Body); err == nil {
			_, _ = fmt.Fprintf(flag.CommandLine.Output(),
				"Content is: %s\n", body)
		}
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Authentication successful!\n")
}
