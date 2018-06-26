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
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/bookingcom/yubistack/cmd"
	"github.com/bookingcom/yubistack/pkg/http"
	yubiauth "github.com/bookingcom/yubistack/pkg/ykauth"
	yubival "github.com/bookingcom/yubistack/pkg/ykval"
)

const (
	// EnvPrefix is the environment prefix used by viper to map fields to environment variables
	EnvPrefix = "YUBISTACK"
	// ServiceName is passed to the logger as a common field
	ServiceName = "yubistack"
	// DefaultConfigPath is the path cobra will look for to find the config file.
	DefaultConfigPath = "/etc/yubico/yubistack.toml"
	pathDecrypt       = "/wsapi/decrypt"
	pathVerify        = "/wsapi/verify"
	pathSync          = "/wsapi/sync"
	pathAuth          = "/wsapi/authenticate"

	// backward compatibility
	pathDecrypt20 = "/wsapi/2.0/decrypt"
	pathVerify20  = "/wsapi/2.0/verify"
	pathSync20    = "/wsapi/2.0/sync"
	pathAuth20    = "/wsapi/2.0/authenticate"

	pathAuthClient = "/yubiauth/client/authenticate"
)

type (
	// Configuration is a mapping of the required fields to create a Yubistack instance
	Configuration struct {
		cmd.Configuration `mapstructure:",squash"`
		cmd.YKValConfig   `mapstructure:"ykval"`
		cmd.YKKSMConfig   `mapstructure:"ykksm"`
		cmd.YKAuthConfig  `mapstructure:"ykauth"`
	}
)

//nolint:golint,gochecknoglobals
var (
	command = &cobra.Command{
		Use:   "yubistack [flags]",
		Short: "Simple golang Yubistack implementation",
		RunE: func(cmd *cobra.Command, args []string) error {
			// https://github.com/spf13/cobra/issues/340
			cmd.SilenceUsage = true
			return run()
		},
	}
)

// nolint:gochecknoinits
func init() {
	flags := command.PersistentFlags()

	flags.String("hostname", "0.0.0.0", "Hostname from which the server will serve ksm")
	flags.String("config", DefaultConfigPath, "Path to a configuration file")

	flags.IntP("port", "p", 8080, "Port on which the server will serve ksm decrypt")
	flags.StringP("level", "l", "info",
		`Set log level, choices are "debug", "info", "warn", "error"`)

	flags.BoolP("debug", "d", false, "Trigger debug logs")
	flags.Bool("no_graphite", false, "Disable graphite reporter")

	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	_ = viper.BindPFlag("hostname", flags.Lookup("hostname"))
	_ = viper.BindPFlag("config", flags.Lookup("config"))
	_ = viper.BindPFlag("port", flags.Lookup("port"))
	_ = viper.BindPFlag("logging.level", flags.Lookup("level"))
	_ = viper.BindPFlag("debug", flags.Lookup("debug"))
	_ = viper.BindPFlag("flags.no_graphite", flags.Lookup("no_graphite"))
}

func matching(ctx *http.Context) bool {
	return ctx.Request.Header.Get(http.HeaderAccept) == http.MimeJSON &&
		(ctx.URL.Path == pathAuth || ctx.URL.Path == pathAuthClient || ctx.URL.Path == pathAuth20)
}

func run() error {
	var config Configuration

	// read and parse config
	viper.SetConfigFile(viper.GetString("config"))
	if err := viper.ReadInConfig(); err != nil {
		return errors.Wrap(err, "failed to read config file")
	}
	if err := viper.Unmarshal(&config); err != nil {
		return errors.Wrap(err, "failed to unmarshal config")
	}
	if err := config.InitOpenTracing(ServiceName); nil != err {
		return errors.Wrap(err, "failed to init opentracing")
	}
	logger := config.Zerolog()
	logger.Debug().Msg("debug mode enabled")
	logger.Debug().Interface("config", config).Msg("loaded config")

	var (
		servers     []cmd.Server
		middlewares = []http.Middleware{cmd.TracingMiddleware, cmd.LoggingMiddleware}
	)
	if !config.Flags.NoGraphite {
		graphite, err := config.NewGraphite(logger)
		if err != nil {
			return errors.Wrap(err, "failed to instantiate graphite")
		}
		if err := graphite.Init(); err != nil {
			return errors.Wrap(err, "failed to init graphite")
		}
		middlewares = append(middlewares, graphite.MiddleWare)
	}

	// setup middlewares
	if prometheus := prometheus(config); prometheus != nil {
		servers = append(servers, prometheus)
		middlewares = append(middlewares, prometheus.Middleware)
	}
	middlewares = append(middlewares, cmd.AuthJSONMiddleware(matching))

	// setup handlers
	ykksm, err := config.YKKSM(logger)
	if err != nil {
		return errors.Wrap(err, "failed to instantiate ykksm")
	}
	loader, ykval, err := config.YKVal(ykksm, logger)
	if err != nil {
		return errors.Wrap(err, "failed to instantiate ykval")
	}
	ykauth, err := config.YKAuth(loader, ykval, logger)
	if err != nil {
		return errors.Wrap(err, "failed to instantiate ykauth")
	}
	dh := http.NewDecryptHandler(func(h *http.DecryptHandler) { h.DecrypterFactory = ykksm })
	vh := http.NewVerifyHandler(func(h *http.VerifyHandler) {
		h.ClientLoaderFactory = loader
		h.VerifierFactory = func(logger zerolog.Logger) yubival.Verifier { return ykval(logger) }
	})
	sh := http.NewSyncHandler(func(h *http.SyncHandler) {
		h.ClientLoaderFactory = loader
		h.SynchronizerFactory = func(logger zerolog.Logger) yubival.Synchronizer { return ykval(logger) }
	})
	ah := http.NewAuthHandler(func(h *http.AuthHandler) {
		h.AuthentifierFactory = func(logger zerolog.Logger) yubiauth.Authentifier { return ykauth(logger) }
		h.AuthorizerFactory = func(logger zerolog.Logger) yubiauth.Authorizer { return ykauth(logger) }
	})
	handlers := map[string]http.Handler{
		pathAuth:    ah,
		pathDecrypt: dh,
		pathVerify:  vh,

		pathSync:      sh,
		pathDecrypt20: dh,
		pathVerify20:  vh,
		pathSync20:    sh,

		pathAuthClient: ah,
	}

	// setup http and (optional) https server(s)
	defaultOptions := config.ServerOptions()
	servers = append(servers, newServer(defaultOptions, middlewares, handlers))
	if tlsOptions := config.TLS.ServerOptions(); tlsOptions != nil {
		servers = append(servers, newServer(append(defaultOptions, tlsOptions...), middlewares, handlers))
	}

	return cmd.StartServers(logger, servers...)
}

func prometheus(config Configuration) *cmd.Prometheus {
	return config.Prometheus(func(prometheus *cmd.Prometheus) {
		ykksm := config.PrometheusConfig.YKKSM()
		ykval := config.PrometheusConfig.YKVal()
		ykauth := config.PrometheusConfig.YKAuth()

		prometheus.Logger = config.Zerolog()
		prometheus.Metrics[pathDecrypt] = ykksm
		prometheus.Metrics[pathSync] = ykval
		prometheus.Metrics[pathAuth] = ykauth

		prometheus.Metrics[pathDecrypt20] = ykksm
		prometheus.Metrics[pathSync20] = ykval
		prometheus.Metrics[pathAuth20] = ykauth
		prometheus.Metrics[pathAuthClient] = ykauth
	})
}

func newServer(options []http.ServerOption, middlewares []http.Middleware, handlers map[string]http.Handler) cmd.Server {
	server := http.NewServer(options...)

	// add middlewares and handlers to our servers
	server.Use(middlewares...)
	for path, handler := range handlers {
		server.Handle(path, handler)
	}
	cmd.RegisterDefaultHealth(server)

	return server
}

func main() {
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
