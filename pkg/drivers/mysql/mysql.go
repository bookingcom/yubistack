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

package mysql

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/rs/zerolog"

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
	// Config is the structure containing the information to create a mysql connection using roster
	Config struct {
		Host     string
		Port     int
		Name     string
		User     string
		Password string
		TLS      bool
	}
	// LoggerFunc is here to catch errors and pipe them to our logger
	// https://github.com/go-sql-driver/mysql/blob/749ddf1598b47e3cd909414bda735fe790ef3d30/errors.go#L43
	LoggerFunc func(v ...interface{})
)

// Print wraps a function to implement Logger interface
func (lf LoggerFunc) Print(v ...interface{}) { lf(v...) }

// Connect use the configuration to initialize a sql.DB connection with MySQL
func (c Config) Connect(logger zerolog.Logger) (*sql.DB, error) {
	err := mysql.SetLogger(LoggerFunc(func(v ...interface{}) {
		logger.Error().Msg(fmt.Sprint(v...))
	}))
	if err != nil {
		return nil, err
	}
	return sql.Open("mysql", c.Addr())
}

func tlsFlag(tls bool) string {
	if tls {
		return "skip-verify"
	}
	return "false"
}

// Addr returns a connect string passed to the sql.Open command
func (c Config) Addr() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?tls=%s", c.User, c.Password,
		c.Host, c.Port, c.Name, tlsFlag(c.TLS))
}

// IsSet is a check to ensure config is properly set up
func (c Config) IsSet() bool {
	return c.Host != "" || c.Port != 0 || c.Name != "" || c.User != "" || c.Password != ""
}

// String is a representation of the connection string with password obfuscated
func (c Config) String() string {
	addr := c.Addr()
	beg := strings.Index(addr, ":")
	end := strings.Index(addr, "@")
	return addr[0:beg] + "*******" + addr[end:]
}
