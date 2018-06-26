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

package ykauth

import "testing"

//nolint:golint,gochecknoglobals
var verifyPasswordEntries = []struct {
	hash, password string
	want           bool
}{
	{
		"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		"Hello world!",
		true,
	},
	{
		"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		"Hello foo!",
		false,
	},
}

func TestVerifyValidPassword(t *testing.T) {
	for _, entry := range verifyPasswordEntries {
		got := VerifyPassword(entry.password, entry.hash)
		if entry.want != got {
			t.Errorf("VerifyPassword(%q, %q) => want %t, got %t",
				entry.password, entry.hash, entry.want, got)
		}
	}
}
