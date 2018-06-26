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
	// include golang exported variables, so it get plugged into graphite
	_ "expvar"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	graphite "github.com/cyberdelia/go-metrics-graphite"
	"github.com/pkg/errors"
	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/http"
)

const (
	metricNSPrefix = "security.yubistack.server.minutely"
	metricInterval = 30 * time.Second
	graphiteURL    = "127.0.0.1:3002"
)

// Graphite structure holds our metrics and is responsible to push it remotely
type (
	Graphite struct {
		registry  goMetrics.Registry
		namespace string
		logger    zerolog.Logger
		interval  time.Duration
	}
)

//nolint:golint,gochecknoglobals
var (
	latencyValues = []float64{0.1, 0.5, 1, 2, 5, 10}
	latencyLabels = []string{"latency.point-one", "latency.point-five", "latency.one",
		"latency.two", "latency.five", "latency.ten"}
)

// NewGraphite creates a new instance of the Graphite structure with sensible defaults
func (c *Configuration) NewGraphite(logger zerolog.Logger) (*Graphite, error) {
	n, err := os.Hostname()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get hostname")
	}
	hostname := strings.Split(n, ".")[0]
	namespace := fmt.Sprintf("%s.%s.", metricNSPrefix, hostname)

	return &Graphite{
		namespace: namespace,
		registry:  goMetrics.NewPrefixedRegistry(namespace),
		logger:    logger,
		interval:  metricInterval,
	}, nil
}

// Init initializes the graphite registry and starts the goroutines to publish GO's debug and runtime stats
func (g *Graphite) Init() error {
	addr, err := net.ResolveTCPAddr("tcp", graphiteURL)
	if err != nil {
		return errors.Wrap(err, "failed to connect graphite url")
	}
	go graphite.Graphite(g.registry, g.interval, "", addr)
	goMetrics.RegisterDebugGCStats(g.registry)
	go goMetrics.CaptureDebugGCStats(g.registry, g.interval)
	goMetrics.RegisterRuntimeMemStats(g.registry)
	go goMetrics.CaptureRuntimeMemStats(g.registry, g.interval)
	return nil
}

// MiddleWare creates a pluggable http.Middleware to catch responses and build metrics
func (g *Graphite) MiddleWare(handler http.HandlerFunc) http.HandlerFunc {
	// returns the last string from path. ex : /wspi/authenticate ->  authenticate
	parsePath := func(path string) string {
		split := strings.Split(path, "/")
		return split[len(split)-1]
	}

	elapsed := func(ctx *http.Context, nano time.Duration, _ error) {
		var (
			path            = parsePath(ctx.URL.Path)
			latencySuffix   = fromLatency(nano.Seconds())
			latency         = fmt.Sprintf("%s.%s", path, latencySuffix)
			pathWithCode    = fmt.Sprintf("%s.%d", path, ctx.Code)
			latencyWithCode = fmt.Sprintf("%s.%s", pathWithCode, latencySuffix)
		)
		goMetrics.GetOrRegisterTimer(path, g.registry).Update(nano)
		goMetrics.GetOrRegisterTimer(pathWithCode, g.registry).Update(nano)
		goMetrics.GetOrRegisterCounter(latency, g.registry).Inc(1)
		goMetrics.GetOrRegisterCounter(latencyWithCode, g.registry).Inc(1)
	}

	return func(ctx *http.Context) (err error) {
		defer func(start time.Time) {
			elapsed(ctx, time.Since(start), err)
		}(time.Now())
		err = handler(ctx)
		return
	}
}

func fromLatency(value float64) string {
	i := sort.SearchFloat64s(latencyValues, value)
	if i == len(latencyLabels) {
		i--
	}
	return latencyLabels[i]
}
