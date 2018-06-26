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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/bookingcom/yubistack/cmd"
	"github.com/bookingcom/yubistack/pkg/http"
)

const (
	// EnvPrefix is the environment prefix used by viper to map fields to environment variables
	EnvPrefix = "YUBIKSM"
	// ServiceName is passed to the logger as a common field
	ServiceName = "yubiksm"
	// DefaultConfigPath is the path cobra will look for to find the config file.
	DefaultConfigPath = "/etc/yubico/yubiksm.toml"

	pathDecrypt = "/wsapi/decrypt"
)

type (
	// Configuration is a mapping of the required fields to create a KSM instance
	Configuration struct {
		cmd.Configuration `mapstructure:",squash"`
		cmd.YKKSMConfig   `mapstructure:",squash"`
	}
)

//nolint:golint,gochecknoglobals
var (
	command = &cobra.Command{
		Use:   "yubiksm [flags]",
		Short: "Simple golang YubiKSM implementation",
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
		defaultOptions = config.ServerOptions()
		servers        []cmd.Server
		middlewares    = []http.Middleware{cmd.TracingMiddleware, cmd.LoggingMiddleware}
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

	ykksm, err := config.YKKSM(logger)
	if err != nil {
		return errors.Wrap(err, "failed to instantiate ykksm")
	}
	handlers := map[string]http.Handler{
		pathDecrypt: http.NewDecryptHandler(func(h *http.DecryptHandler) {
			h.DecrypterFactory = ykksm
		}),
	}
	servers = append(servers, cmd.NewServer(defaultOptions, middlewares, handlers))

	if prometheus := prometheus(config); prometheus != nil {
		servers = append(servers, prometheus)
		middlewares = append(middlewares, prometheus.Middleware)
	}

	if tlsOptions := config.TLS.ServerOptions(); tlsOptions != nil {
		servers = append(servers, cmd.NewServer(append(defaultOptions, tlsOptions...), middlewares, handlers))
	}

	return cmd.StartServers(logger, servers...)
}

func prometheus(config Configuration) *cmd.Prometheus {
	return config.Prometheus(func(prometheus *cmd.Prometheus) {
		ykksm := config.PrometheusConfig.YKKSM()

		prometheus.Logger = config.Zerolog()
		prometheus.Metrics[pathDecrypt] = ykksm
	})
}

func main() {
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
