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

import "github.com/bookingcom/yubistack/pkg/http"

// PathHealth indicates the health endpoint.
const PathHealth = "/health"

// HealthHandler is used for serving the application status for telegraf or other monitoring systems.
var HealthHandler = http.HandlerFunc(func(ctx *http.Context) error { //nolint:golint,gochecknoglobals
	_, _ = ctx.Response.WriteString("OK")
	return nil
})

// RegisterDefaultHealth registers a default health endpoint to http server.
func RegisterDefaultHealth(server *http.Server) {
	server.Handle(PathHealth, HealthHandler)
}
