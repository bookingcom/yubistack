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

package sqlite

import (
	"database/sql"

	// load the sqlite driver
	_ "github.com/mattn/go-sqlite3"

	"github.com/bookingcom/yubistack/pkg/drivers"
)

//nolint:golint,gochecknoglobals
var (
	// NewYKKSM is an alias for the global YKKSM sql driver structure
	NewYKKSM = drivers.NewYKKSM
	// NewYKVal is an alias for the global YKVal sql driver structure
	NewYKVal = drivers.NewYKVal
	// NewYKAuth is an alias for the global YKAuth sql driver structure
	NewYKAuth = drivers.NewYKAuth
)

type (
	// Config is the structure containing the information to create a sqlite connection
	Config struct {
		File string
	}
)

// Connect use the configuration to initialize a sql.DB  connection with sqlite
func (c Config) Connect() (*sql.DB, error) { return sql.Open("sqlite3", c.File) }

// IsSet is a check to ensure config is properly set up
func (c Config) IsSet() bool { return c.File != "" }
