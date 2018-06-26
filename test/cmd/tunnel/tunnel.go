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
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

//nolint:golint,gochecknoglobals
var (
	clients  = "localhost:8080"
	starting = 3000
	username = ""
)

// nolint:gochecknoinits
func init() {
	flag.StringVar(&username, "u", username, "user to use for ssh connection, if not specified current user is taken.")
	flag.StringVar(&clients, "c", clients, "comma separated list of hosts to tunnel to with specified port.")
	flag.IntVar(&starting, "s", starting, "the starting port from which the script will iterate clients to forward to.")

	flag.Parse()
}

func config(name string) (*ssh.ClientConfig, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	client := agent.NewClient(conn)
	return &ssh.ClientConfig{
		User: name,
		Auth: []ssh.AuthMethod{
			// Use a callback rather than PublicKeys
			// so we only consult the agent once the remote server
			// wants it.
			ssh.PublicKeysCallback(client.Signers),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				// Just send the password back for all questions
				answers := make([]string, len(questions))
				for i, question := range questions {
					fmt.Print(question)
					if _, err := fmt.Scan(&answers[i]); err != nil {
						return nil, err
					}
				}
				return answers, nil
			}),
		},
		// nolint:gosec
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func interrupt() chan struct{} {
	interrupt := make(chan os.Signal)
	done := make(chan struct{})
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		close(done)
	}()
	return done
}

func tunnel(conn *ssh.Client, local, remote string) {
	listener, err := net.Listen("tcp", ":"+local)
	if err != nil {
		log.Printf("failed to establish local port forwarding connection: %q", err)
		return
	}

	for {
		here, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept local port forwarding connection: %q", err)
			continue
		}
		go func(here net.Conn) {
			there, err := conn.Dial("tcp", "localhost:"+remote)
			if err != nil {
				log.Printf("failed to establish remote port forwarding connection: %q", err)
				return
			}
			// bidirectional copying
			go func() {
				if _, err := io.Copy(here, there); err != nil {
					log.Printf("stream copy failed from remote to local: %q", err)
				}
				// clean()
			}()
			go func() {
				if _, err := io.Copy(there, here); err != nil {
					log.Printf("stream copy failed local to remote: %q", err)
				}
				// clean()
			}()
		}(here)
	}
}

func split(addr string) (host, port string, err error) {
	if spitted := strings.SplitN(addr, ":", 2); len(spitted) != 2 {
		err = fmt.Errorf("wrong address string, expect %q, got: %q", "some.remote.xyz:1111", addr)
	} else {
		host, port = spitted[0], spitted[1]
	}
	return
}

func main() {
	if username == "" {
		if current, err := user.Current(); err != nil {
			log.Fatalf("failed to retrieve user for ssh connection: %q", err)
		} else {
			username = current.Name
		}
	}
	conf, err := config(username)
	if err != nil {
		log.Fatalf("failed to initialize connection to ssh agent: %q", err)
	}
	for i, client := range strings.Split(clients, ",") {
		host, port, err := split(client)
		if err != nil {
			log.Fatalf("%s", err)
		}
		conn, err := ssh.Dial("tcp", host+":22", conf)
		if err != nil {
			log.Fatalf("failed to initialize ssh connection to %q: %q", host, err)
		}
		log.Printf("established connection for: %q", client)
		go tunnel(conn, strconv.Itoa(starting+i), port)
	}
	<-interrupt()
}
