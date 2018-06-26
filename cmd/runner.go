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

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/rs/zerolog"
)

var (
	// ErrInterrupt is returned when interrupt signal is caught
	ErrInterrupt = fmt.Errorf("interrupt")
)

type (
	// Server interface is used as a task by the runner, it performs a start and stop
	Server interface {
		ListenAndServe() error
		Shutdown(context.Context) error
	}
)

func startServers(errs chan error, servers ...Server) func() {
	for _, server := range servers {
		go func(server Server) {
			if err := server.ListenAndServe(); err != nil {
				errs <- err
			}
		}(server)
	}

	// this function is not thread safe ensure that you are not calling this from
	// different thread.
	stopping := false
	return func() {
		if stopping {
			return
		}
		stopping = true
		for _, server := range servers {
			if err := server.Shutdown(context.Background()); err != nil {
				errs <- err
			}
		}
		close(errs)
	}
}

// StartServers starts multiple Server instances.
// It listen on os.Interrupt in order to stops all the servers managed.
func StartServers(logger zerolog.Logger, servers ...Server) error {
	errs, err := make(chan error), fmt.Errorf("an error occurred")

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		<-interrupt
		_, _ = os.Stdout.Write([]byte{'\n'})
		errs <- ErrInterrupt
	}()
	cancel := startServers(errs, servers...)

	for e := range errs { // this will execute until the errs channel is closed
		logger.Error().Msgf("%s", e)
		cancel()
		if e == ErrInterrupt {
			err = nil
		}
	}
	return err
}
