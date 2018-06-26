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
	"fmt"
	"io"
	"log"
	"time"
)

const (
	inFmt = "%s %s key: %s request: %d, elapsed: %s"
)

type (
	// Line is a structure storing the values of the text response of a KSM module
	Line struct {
		DateTime time.Time
		Public   string
		Elapsed  time.Duration
		Request  int
	}
)

func main() {
	lines := make([]Line, 0)
	for {
		line, date, hour, elapsed := Line{}, "", "", ""
		_, err := fmt.Scanf(inFmt, &date, &hour, &line.Public, &line.Request, &elapsed)

		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if err == nil {
			line.DateTime, err = time.Parse("2006/01/02 15:04:05", date+" "+hour)
			if err != nil {
				log.Fatalf("failed to parse datetime: %q", err)
			}
			line.Elapsed, err = time.ParseDuration(elapsed)
			if err != nil {
				log.Fatalf("failed to parse elapsed: %q", err)
			}
			lines = append(lines, line)
			continue
		}
		// log.Printf("failed to scan input: %q", err)
	}
	log.Printf("scanned %d entries", len(lines))
	accumulator := int64(0)
	for _, line := range lines {
		accumulator += int64(line.Elapsed)
	}
	log.Printf("average latency: %s", time.Duration(accumulator/int64(len(lines))))
}
