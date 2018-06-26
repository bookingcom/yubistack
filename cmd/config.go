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
	"database/sql"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog"
	"github.com/uber/jaeger-client-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	"github.com/uber/jaeger-lib/metrics"

	"github.com/bookingcom/yubistack/pkg/drivers"
	"github.com/bookingcom/yubistack/pkg/drivers/mysql"
	"github.com/bookingcom/yubistack/pkg/drivers/sqlite"
	"github.com/bookingcom/yubistack/pkg/http"
	"github.com/bookingcom/yubistack/pkg/util"
	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

var (
	// ErrNoDriver is returned when no database driver is found in config
	ErrNoDriver = fmt.Errorf("no driver found in configuration")
	// ErrMalformedRetriever is returned when a retriever configuration is not valid
	ErrMalformedRetriever = fmt.Errorf("malformed retriever")
	//nolint:golint,gochecknoglobals
	// https://www.loggly.com/blog/logging-in-new-style-daemons-with-systemd/
	lvlMapJournald = map[zerolog.Level][]byte{
		zerolog.DebugLevel: []byte("<7>"),
		zerolog.InfoLevel:  []byte("<6>"),
		zerolog.WarnLevel:  []byte("<4>"),
		zerolog.ErrorLevel: []byte("<3>"),
		zerolog.FatalLevel: []byte("<0>"),
		zerolog.PanicLevel: []byte("<0>"),
		zerolog.NoLevel:    []byte("<6>"),
	}
	//nolint:golint,gochecknoglobals
	lvlMap = map[string]zerolog.Level{
		"debug": zerolog.DebugLevel, "info": zerolog.InfoLevel,
		"warn": zerolog.WarnLevel, "error": zerolog.ErrorLevel, "": zerolog.PanicLevel,
	}
)

const (
	mySQL   = "mysql"
	sqlLite = "sqlite"
)

type (
	// Configuration is a the basic structure of fields for the yubistack modules
	Configuration struct {
		Debug            bool
		Hostname         string
		Port             int
		PrometheusConfig `mapstructure:"prometheus"`
		Logging          struct {
			Level string
			Type  string
		}
		TLS   *TLSConfig `mapstructure:"tls"`
		Flags struct {
			NoGraphite bool `mapstructure:"no_graphite"`
		}
	}
	// TLSConfig is a substructure for configuring TLS
	TLSConfig struct {
		Port     int
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	}
	// YKKSMConfig contains YKKSM specific configuration fields
	YKKSMConfig struct {
		PrivateKey string `mapstructure:"private_key"`
		Retrievers []map[string]string
		DBConfig   `mapstructure:",squash"`
	}
	// YKValConfig contains YKVal specific configuration fields
	YKValConfig struct {
		Servers  []string
		DBConfig `mapstructure:",squash"`
	}
	// YKAuthConfig contains YKAuth specific configuration fields
	YKAuthConfig struct {
		ClientID  uint64 `mapstructure:"client_id"`
		SyncLevel string `mapstructure:"sync_level"`
		Timeout   int
		DBConfig  `mapstructure:",squash"`
	}
	// DBConfig is a substructure for configuring the database connections
	DBConfig struct {
		Mysql  mysql.Config
		Sqlite sqlite.Config
	}
	// JournaldLevelWriter is a structure to write down to systemd journal format
	JournaldLevelWriter struct {
		io.Writer
	}
	// ErrMultipleDrivers is returned when there is more than one driver for a specific connection
	ErrMultipleDrivers []string
	// YKValFactory is currying a YKVal creation to inject a logger on each request
	YKValFactory func(logger zerolog.Logger) *ykval.YKVal
	// YKAuthFactory is currying a YKAuth creation to inject a logger on each request
	YKAuthFactory func(logger zerolog.Logger) *ykauth.YKAuth
)

// ServerOptions is transforming a TLSConfig into a slice of http.ServerOption
func (c *TLSConfig) ServerOptions() []http.ServerOption {
	if c == nil || c.Port == 0 || c.CertFile == "" {
		return nil
	}

	return []http.ServerOption{
		func(s *http.Server) {
			host, _, _ := net.SplitHostPort(s.Addr)
			s.Addr = net.JoinHostPort(host, strconv.Itoa(c.Port))
		},
		http.WithTLS(c.CertFile, c.KeyFile),
	}
}

// WriteLevel makes JournalLevelWriter a zerolog writer and convert log entry to journald format
func (jlw *JournaldLevelWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level == zerolog.Disabled {
		return len(p), nil
	}
	return jlw.Write(append(lvlMapJournald[level], p...))
}

// Error implement the error interface
func (e ErrMultipleDrivers) Error() string {
	return fmt.Sprintf(
		"got multiple driver definition in configuration: %s",
		strings.Join(e, ", "),
	)
}

// Zerolog wraps the functionality for logging with different levels.
func (c Configuration) Zerolog() zerolog.Logger {
	level := lvlMap[c.Logging.Level]
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	switch {
	case c.Debug:
		level = zerolog.DebugLevel
		logger = logger.With().Timestamp().Logger()
	case c.Logging.Type == "syslog":
		writer, err := syslog.New(0, path.Base(os.Args[0]))
		if err != nil {
			panic(err)
		}
		logger = zerolog.New(zerolog.SyslogLevelWriter(writer))
	case c.Logging.Type == "journald":
		logger = zerolog.New(&JournaldLevelWriter{os.Stderr})
	default:
		logger = zerolog.New(os.Stderr)
	}
	return logger.With().Logger().Level(level)
}

func (c YKKSMConfig) transformers() ([]ykksm.Transformer, error) {
	list := make([]ykksm.Transformer, len(c.Retrievers))
	for i, retriever := range c.Retrievers {
		switch retriever["name"] {
		case "hex":
			list[i] = ykksm.HexTransformer
		case "rsa":
			path, ok := retriever["path"]
			if !ok {
				return nil, ErrMalformedRetriever
			}
			key, err := util.ReadRSAKeyFromFile(path)
			if err != nil {
				return nil, err
			}
			list[i] = ykksm.OAEPTransformer(key)
		case "base64":
			list[i] = ykksm.Base64Transformer
		default:
			return nil, ErrMalformedRetriever
		}
	}
	return list, nil
}

// YKKSM transform a YKKSMConfig into a http.DecrypterFactory
func (c YKKSMConfig) YKKSM(logger zerolog.Logger) (ykksm.DecrypterFactory, error) {
	var retriever func(logger zerolog.Logger) ykksm.Retriever
	var opt = func(logger zerolog.Logger) func(ksm *drivers.YKKSM) {
		return func(ksm *drivers.YKKSM) { ksm.Logger = logger }
	}
	var db, driver, err = c.NewDB(logger)

	if err != nil {
		return nil, err
	}
	transformers, err := c.transformers()
	if err != nil {
		return nil, err
	}
	switch driver {
	case mySQL:
		retriever = func(logger zerolog.Logger) ykksm.Retriever {
			return mysql.NewYKKSM(db, opt(logger))
		}
	case sqlLite:
		retriever = func(logger zerolog.Logger) ykksm.Retriever {
			return sqlite.NewYKKSM(db, opt(logger))
		}
	default:
		return nil, ErrNoDriver
	}
	return func(logger zerolog.Logger) ykksm.Decrypter {
		return ykksm.NewKSM(
			ykksm.RetrieveTransformer(retriever(logger), transformers...),
			func(ksm *ykksm.YKKSM) { ksm.Logger = logger })
	}, nil
}

// YKVal transform a YKValConfig into a pkg.ClientLoaderFactory and YKValFactory
func (c YKValConfig) YKVal(decrypter ykksm.DecrypterFactory, logger zerolog.Logger) (http.ClientLoaderFactory, YKValFactory, error) {
	opt := func(logger zerolog.Logger) func(ykauth *drivers.YKVal) {
		return func(ykauth *drivers.YKVal) { ykauth.Logger = logger }
	}
	db, driver, err := c.NewDB(logger)
	if err != nil {
		return nil, nil, err
	}
	switch driver {
	case mySQL:
		loader := func(logger zerolog.Logger) yubico.ClientLoader {
			return mysql.NewYKVal(db, opt(logger))
		}
		mapper := func(logger zerolog.Logger) yubico.YubikeyDBMapper {
			return mysql.NewYKVal(db, opt(logger))
		}
		return loader, func(logger zerolog.Logger) *ykval.YKVal {
			return ykval.NewYKVal(mapper, func(ykval *ykval.YKVal) {
				ykval.Logger = logger
				ykval.DecrypterFactory = decrypter
				ykval.Servers = c.Servers
			})
		}, nil
	case sqlLite:
		loader := func(logger zerolog.Logger) yubico.ClientLoader {
			return sqlite.NewYKVal(db, opt(logger))
		}
		mapper := func(logger zerolog.Logger) yubico.YubikeyDBMapper {
			return sqlite.NewYKVal(db, opt(logger))
		}
		return loader, func(logger zerolog.Logger) *ykval.YKVal {
			return ykval.NewYKVal(mapper, func(ykval *ykval.YKVal) {
				ykval.Logger = logger
				ykval.DecrypterFactory = decrypter
				ykval.Servers = c.Servers
			})
		}, nil
	default:
		return nil, nil, ErrNoDriver
	}
}

// YKAuth transform a YKAuthConfig into a YKAuthFactory
func (c YKAuthConfig) YKAuth(
	fetcher http.ClientLoaderFactory, val YKValFactory, logger zerolog.Logger,
) (YKAuthFactory, error) {
	var loader func(zerolog.Logger) yubico.UserLoader
	var opt = func(logger zerolog.Logger) func(ykauth *drivers.YKAuth) {
		return func(ykauth *drivers.YKAuth) { ykauth.Logger = logger }
	}
	sync, err := ykval.ParseSyncString(strings.ReplaceAll(c.SyncLevel, "%", ""))
	if err != nil {
		return nil, err
	}
	db, driver, err := c.NewDB(logger)
	if err != nil {
		return nil, err
	}
	client, err := fetcher(logger).LoadClient(c.ClientID)
	if err != nil {
		return nil, err
	}
	switch driver {
	case "mysql":
		loader = func(logger zerolog.Logger) yubico.UserLoader { return mysql.NewYKAuth(db, opt(logger)) }
	case "sqlite":
		loader = func(logger zerolog.Logger) yubico.UserLoader { return sqlite.NewYKAuth(db, opt(logger)) }
	default:
		return nil, ErrNoDriver
	}
	return func(logger zerolog.Logger) *ykauth.YKAuth {
		return ykauth.NewYKAuth(client, func(auth *ykauth.YKAuth) {
			auth.Logger = logger
			auth.Verifier = val(logger)
			auth.UserLoader = loader(logger)
		}, ykauth.SyncOpt(sync), ykauth.TimeoutOpt(c.Timeout))
	}, nil
}

func (c DBConfig) driver() (string, error) {
	var collected []string
	if c.Sqlite.IsSet() {
		collected = append(collected, "sqlite")
	}
	if c.Mysql.IsSet() {
		collected = append(collected, "mysql")
	}
	switch len(collected) {
	case 0:
		return "", ErrNoDriver
	case 1:
		return collected[0], nil
	default:
		return "", ErrMultipleDrivers(collected)
	}
}

// NewDB transform a DBConfig on an initialize sql.DB connection
// This function tries multiple drivers to create the effective connection
// and return an error if something goes wrong.
func (c DBConfig) NewDB(logger zerolog.Logger) (db *sql.DB, driver string, err error) {
	driver, err = c.driver()
	if err != nil {
		logger.Error().Err(err).Msg("failed inferring driver")
	}
	logger = logger.With().Str("db", driver).Logger()
	switch driver {
	case "sqlite":
		logger.Info().Str("file", c.Sqlite.File).Msg("initializing connection")
		db, err = c.Sqlite.Connect()
		if err != nil {
			logger.Error().Err(err).Str("file", c.Sqlite.File).Msgf("can't connect")
			return
		}
		return
	case "mysql":
		logger.Info().Str("string", c.Mysql.String()).Msg("initializing connection")
		// TODO: find a better way to do this. Currently overriding the module identifier
		db, err = c.Mysql.Connect(logger.With().Str("module", "mysql").Logger())
		if err != nil {
			logger.Error().Err(err).Str("string", c.Mysql.String()).Msgf("can't connect")
			return
		}
		// https://github.com/go-sql-driver/mysql/issues/674#issuecomment-489830198
		db.SetConnMaxLifetime(10 * time.Second)
		db.SetMaxIdleConns(0)
		return
	default:
		logger.Error().Err(ErrNoDriver).Msg("can't connect")
		return db, driver, ErrNoDriver
	}
}

// InitOpenTracing creates a tracer from configuration and set it up globally
func (c Configuration) InitOpenTracing(serviceName string) error {
	cfg := jaegercfg.Configuration{
		ServiceName: serviceName,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
	}

	tracer, _, err := cfg.NewTracer(
		jaegercfg.Reporter(jaeger.NewNullReporter()), // Currently reporting is disabled
		jaegercfg.Metrics(metrics.NullFactory),       // Not publishing the opentracing metrics anywhere
	)
	if nil != err {
		return err
	}
	opentracing.SetGlobalTracer(tracer)
	return nil
}

// ServerOptions returns the default options with want to pass to the server structure
func (c Configuration) ServerOptions() []http.ServerOption {
	return []http.ServerOption{
		func(s *http.Server) {
			s.Addr = net.JoinHostPort(c.Hostname, strconv.Itoa(c.Port))
			s.Logger = c.Zerolog()
			s.ErrorLog = HTTPErrorLogger(c.Zerolog())
		},
	}
}

// NewServer is an util function to create a server with options
func NewServer(options []http.ServerOption, middlewares []http.Middleware, handlers map[string]http.Handler) Server {
	server := http.NewServer(options...)

	// add middlewares and handlers to our servers
	server.Use(middlewares...)
	for path, handler := range handlers {
		server.Handle(path, handler)
	}
	RegisterDefaultHealth(server)

	return server
}
