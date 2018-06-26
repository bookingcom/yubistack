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

import "testing"

func TestLabelProvider(t *testing.T) {
	tests := []struct {
		name          string
		latency       float64
		expectedLabel string
	}{
		{
			name:          "point-one below",
			latency:       0.01,
			expectedLabel: "latency.point-one",
		},
		{
			name:          "point-one equals",
			latency:       0.1,
			expectedLabel: "latency.point-one",
		},
		{
			name:          "point-one above",
			latency:       0.11,
			expectedLabel: "latency.point-five",
		},
		{
			name:          "point-five below",
			latency:       0.4,
			expectedLabel: "latency.point-five",
		},
		{
			name:          "point-five equals",
			latency:       0.5,
			expectedLabel: "latency.point-five",
		},
		{
			name:          "point-five above",
			latency:       0.6,
			expectedLabel: "latency.one",
		},
		{
			name:          "one below",
			latency:       0.99,
			expectedLabel: "latency.one",
		},
		{
			name:          "one equals",
			latency:       1,
			expectedLabel: "latency.one",
		},
		{
			name:          "above 1",
			latency:       1.1,
			expectedLabel: "latency.two",
		},
		{
			name:          "below two",
			latency:       1.99,
			expectedLabel: "latency.two",
		},
		{
			name:          "equals two",
			latency:       2,
			expectedLabel: "latency.two",
		},
		{
			name:          "above two",
			latency:       2.1,
			expectedLabel: "latency.five",
		},
		{
			name:          "below five",
			latency:       4.99,
			expectedLabel: "latency.five",
		},
		{
			name:          "equals five",
			latency:       5,
			expectedLabel: "latency.five",
		},
		{
			name:          "above five",
			latency:       5.1,
			expectedLabel: "latency.ten",
		},
		{
			name:          "below ten",
			latency:       9.99,
			expectedLabel: "latency.ten",
		},
		{
			name:          "equals ten",
			latency:       10,
			expectedLabel: "latency.ten",
		},
		{
			name:          "above ten",
			latency:       10.1,
			expectedLabel: "latency.ten",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			label := fromLatency(tt.latency)
			if label != tt.expectedLabel {
				t.Errorf("for latency %f, expected label %s. Got %s", tt.latency, tt.expectedLabel, label)
			}
		})
	}
}
