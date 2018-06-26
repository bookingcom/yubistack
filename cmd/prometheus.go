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
	"log"
	httpStd "net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/http"
	"github.com/bookingcom/yubistack/pkg/util"
)

const (
	// nanosecond to second conversion factor (1ns = 1*10-9s)
	nanoToSec = 0.000000001
)

type (
	// PrometheusConfig is a structure to configure our prometheus instance
	PrometheusConfig struct {
		Prefix   string
		Hostname string
		Port     int
	}
	// HistVec is an alias for prometheus.HistogramVec
	HistVec = prometheus.HistogramVec
	// Prometheus is the structure we use to deal with Prometheus
	Prometheus struct {
		zerolog.Logger
		server  *httpStd.Server
		Metrics map[string]*prometheus.HistogramVec
	}
)

// YKKSM function creates the HistogramVectors for the YKKSM module
func (c PrometheusConfig) YKKSM() *HistVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    c.Prefix + "decrypt_duration_seconds",
		Help:    "Time to decrypt an otp",
		Buckets: []float64{0.1, 0.5, 1, 5, 10}, // defining small buckets as this app should not take more than 1 sec to respond
	}, []string{"code"}) // this will be partitioned by the HTTP code.
}

// YKVal function creates the HistogramVectors for the YKVal module
func (c PrometheusConfig) YKVal() *HistVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    c.Prefix + "sync_duration_seconds",
		Help:    "Time to sync otp",
		Buckets: []float64{0.1, 0.5, 1, 5, 10}, // defining small buckets as this app should not take more than 1 sec to respond
	}, []string{"code"}) // this will be partitioned by the HTTP code.
}

// YKAuth function creates the HistogramVectors for the YKAuth module
func (c PrometheusConfig) YKAuth() *HistVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    c.Prefix + "auth_duration_seconds",
		Help:    "Time to authenticate user/otp",
		Buckets: []float64{0.1, 0.5, 1, 5, 10}, // defining small buckets as this app should not take more than 1 sec to respond
	}, []string{"code"}) // this will be partitioned by the HTTP code.
}

func register(metrics map[string]*HistVec) {
	seen := map[*HistVec]struct{}{}
	for _, metric := range metrics {
		if _, ok := seen[metric]; ok {
			continue
		}
		prometheus.MustRegister(metric)
		seen[metric] = struct{}{}
	}
}

// Prometheus function creates an instance of Prometheus structure from config
func (c PrometheusConfig) Prometheus(options ...func(*Prometheus)) *Prometheus {
	if c.Port == 0 {
		return nil
	}
	p := &Prometheus{zerolog.Nop(), nil, map[string]*HistVec{}}
	for _, option := range options {
		option(p)
	}
	register(p.Metrics)
	p.server = &httpStd.Server{
		Handler:  promhttp.Handler(),
		Addr:     fmt.Sprintf("%s:%d", c.Hostname, c.Port),
		ErrorLog: HTTPErrorLogger(p.Logger),
	}
	return p
}

// HTTPErrorLogger creates a logger for HTTP errors piping to Prometheus
func HTTPErrorLogger(logger zerolog.Logger) *log.Logger {
	return log.New(util.WriterFunc(func(buf []byte) (int, error) {
		logger.Error().Msg(string(buf))
		return len(buf), nil
	}), "", 0)
}

// ListenAndServe listens on the TCP network address and serve Prometheus metrics
func (p *Prometheus) ListenAndServe() error {
	p.Info().Str("addr", p.server.Addr).Msg("serving prometheus")
	return p.server.ListenAndServe()
}

// Shutdown stops the server in a clean fashion
func (p *Prometheus) Shutdown(ctx context.Context) error { return p.server.Shutdown(ctx) }

// Middleware creates a middleware out of the current structure.
// It allows us to plug in our server and infer metrics from requests.
func (p *Prometheus) Middleware(next http.HandlerFunc) http.HandlerFunc {
	// push metrics to a prometheus histogram if it matches the context URL path.
	// the metrics is the time elapsed between the starting measure, passed as an
	// argument and the moment the function is executed.
	measure := func(ctx *http.Context, start time.Time) {
		if hist, ok := p.Metrics[ctx.URL.Path]; ok {
			elapsed := float64(time.Since(start)) * nanoToSec
			ctx.Debug().Str("method", ctx.Method).
				Str("path", ctx.URL.Path).Float64("elapsed", elapsed).
				Msg("request end")
			hist.WithLabelValues(strconv.Itoa(ctx.Code)).Observe(elapsed)
		}
	}
	return func(ctx *http.Context) error {
		defer measure(ctx, time.Now())
		return next(ctx)
	}
}
