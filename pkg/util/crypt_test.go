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

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/bookingcom/yubistack/internal"
)

const (
	rsaTest = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqhOY9FvnDkPao59AmLDJlnPySd3FXwSXQCVzQsxpQTaTrcDH
G4MT4Re/wWddR6/R/U/W83DV4OITEmigFFeHOULeECeBe2WNK3X4wMqq1gjjOSKg
WjHc+q9GSPbPw+rU6Pw6U22omI3G/aZdg5pz6cLXsYNfN9XD60QzjnstKjY5cStO
L8DT0aDbdqHK6mEM92n9d/cT8ms+7QOt2ssYq2Q52KDWamrZz0lk62GhU8Q4hE5u
At9E3LZYk8hxvwuJ6fsFqTMeyicq2Y+Fj/+bjkREdmol8WkYvN+fH8H1UmpKE99H
bsa4jCuPpHOAKRnHpXAK94RYhgsy5bcDDQo9FwIDAQABAoIBAG7DLpTNmW+f3y86
Ur5ePBsAzeUvSg/0lHBRM3xoVZAD9C9vYfxX5EVuyxIwt/4s0gwvx+RpMtEvSo5t
lvtIeadgFfDdWaU8YLDSNruQAaw8w4Z9N4MmAC0+ov53xp1oPVqykWWt/+PCSbr9
ct93Yk/19bUEwqlBTUPV+eGr9KEM+OU15mX50C0H9BNczVql2Ma/DhH2w0mLUhV2
rci4P///rFuh/DAM/2V+4ZxNslcTYV8BcKmP0FB+MbS6D6SVFe5ULvJ0iacDCHsf
bU4hVhNS4MtqnVFCPHGuY5Sy9BWm80THyRce8WDqWJBEIyGRinSEYWZVlIcm9DHe
BoFnQFkCgYEA4DMCk1wovnhuNA9CQelgXFW/dqrFkObId30qJp7uzLUP5Qtm1c7x
PMrItfNoN197Ye/qi9xHcJ4ZkZLvlM6GLyEkEYPO4ov4+d3CpfiAsRoxTo3XFPAP
d78mMD56xlfbzt+dGzcvILHFlP49u8gzT/6RjTAZSWGZGLM3LWzy71MCgYEAwjNQ
435eEGCFSBHnEsZiGD4+mZTD7uY9oyNuSe6ZrDwBBGD8INQKeuFOCS1fW5cmROX1
OPpCVaStVKJbM/p6rNWgbivWIuwO0y4fuhzvYgBUyzN5kIkCXCcZdZRHWk323uRr
Qnt0ApgXn+JS2VTMXTA5VNB/0CEPWXP9crKxNq0CgYBepAnVTNUCOnJC1aIhkrOT
prrRDBukJFfBYPu3G+YwUcpo5Jw/a0EYaX26mQqIPW0nFZDMA2vA1WxzsDQke93W
7UV9g0eFCJNMXtl5GGKy4ByqTWPauc+9u9oSCX3oVlQ6itiWEYB6a7C9SWmj6EoI
3axxjjlOab2n2JdVPKV8cwKBgFsG8LBhqDem9nJMqfI7+PkCHBejCqAtXdDdJ7IR
3AhGa/egei3tFih4+ToGAX+N/ssmuuYFMBiywug73eIkU2I2FCfv9kSSP3SvVwHG
1FIsc5J3w1CDWA7X6PAbG8LxbnkVuk0ETuF0ZwZzcIAcZlp74zOlM3PcOzSj0LX1
mmlVAoGAJxopOvh1GPKjD+v9WvKb/K0kErozrdGajq6Cu0u3hmBRstYydTqg/Dcn
4unuxl9hSgZPVRRkXQLEECLr5KgxgWf2KQH6FPR+aVO3+KBgNioCVOecrwO/M4mz
moNeFBb2flsNipe7Swkc8/dglsMgKMnxxbHL3j03FhTd+jVr6kI=
-----END RSA PRIVATE KEY-----`
)

//nolint:golint,gochecknoglobals
var rsaExp, _ = big.NewInt(0).SetString(
	"139824613569886256929565319778115395984209024274962001878614089999"+
		"50512718965233544136443130587273021448939302638909517772422665754"+
		"09913797909796103083260536866826834910920585263205696870442622195"+
		"44005319956019660699438239692832457506017936833916378568871382423"+
		"13724839686275781545184300752059524859121879924234933843092800106"+
		"17304842490924322366132474881957252215514877516918248690259781080"+
		"96168572715501112212349599350464445691758741514280177772440896463"+
		"52158708191797180972653869440889589193288142526808188283112676783"+
		"56294614280241548896898160781726948980391138493899772834927198980"+
		"0946383426939323719432689631321", 10)

//nolint:golint,gochecknoglobals
// rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte("foo"), []byte(""))
var oapTest = []byte{
	44, 88, 162, 86, 119, 131, 224, 92, 242, 253, 217, 107, 179, 110, 5, 141,
	80, 214, 1, 238, 5, 43, 153, 53, 223, 166, 192, 247, 252, 178, 179, 14, 134,
	79, 240, 168, 131, 180, 139, 222, 55, 48, 4, 45, 225, 178, 249, 152, 106,
	84, 39, 89, 196, 53, 21, 122, 125, 171, 122, 190, 121, 56, 236, 141, 120,
	92, 226, 171, 192, 78, 192, 54, 82, 238, 170, 157, 150, 79, 188, 34, 163,
	125, 35, 248, 255, 37, 230, 180, 159, 224, 248, 127, 85, 72, 35, 137, 221,
	19, 2, 79, 173, 239, 161, 95, 61, 155, 168, 199, 130, 190, 3, 29, 122, 242,
	209, 9, 187, 175, 197, 34, 14, 206, 175, 168, 183, 30, 46, 94, 230, 109,
	216, 82, 151, 93, 105, 135, 182, 87, 9, 193, 50, 83, 127, 194, 152, 252,
	237, 107, 169, 11, 32, 92, 25, 57, 5, 83, 136, 21, 143, 51, 39, 184, 77,
	55, 169, 24, 82, 206, 110, 39, 53, 78, 4, 124, 164, 38, 136, 12, 119, 163,
	121, 53, 152, 254, 157, 42, 24, 38, 178, 26, 128, 6, 248, 94, 139, 10, 103,
	11, 50, 173, 83, 68, 45, 142, 117, 162, 80, 211, 110, 159, 90, 103, 102,
	204, 102, 10, 27, 59, 1, 89, 16, 200, 179, 66, 166, 174, 245, 88, 42, 172,
	200, 73, 70, 11, 145, 92, 235, 32, 74, 1, 53, 64, 166, 227, 55, 254, 220,
	39, 90, 166, 128, 202, 234, 192, 14, 252,
}

//nolint:golint,gochecknoglobals
var entriesRSARetriever = []struct {
	cypher []byte
	out    []byte
	err    error
}{
	{
		oapTest, []byte("foo"), nil,
	},
	{
		append(oapTest, 255), nil,
		fmt.Errorf("crypto/rsa: decryption error"),
	},
}

func TestDecodeRSAOAEP(t *testing.T) {
	key, err := DecodeRSAKey([]byte(rsaTest))
	if err != nil {
		t.Fatalf("failed to parse testing rsa key: %q", err)
	}
	for _, entry := range entriesRSARetriever {
		out, err := DecodeRSAOAEP(key, entry.cypher)
		if string(out) != string(entry.out) || !internal.ErrEqual(err, entry.err) {
			t.Errorf("DecodeRSAOAEP(%s, %q) want: %q, %s - got: %q, %s",
				internal.TestRSA(key), entry.cypher[:10],
				entry.out, internal.TestError(entry.err),
				out, internal.TestError(err))
		}
	}
}

//nolint:golint,gochecknoglobals
var entriesReadRSAKey = []struct {
	file func(*testing.T, func(string)) error
	key  *rsa.PrivateKey
	err  error
}{
	{func(_ *testing.T, cb func(string)) error {
		cb("/foo/bar")
		return nil
	}, nil,
		fmt.Errorf("open /foo/bar: no such file or directory")},
	{
		func(t *testing.T, cb func(string)) error {
			return internal.TempFile(t, func(f *os.File) error {
				cb(f.Name())
				return nil
			})
		}, nil, ErrPEMDecode,
	},
	{
		func(t *testing.T, cb func(string)) error {
			return internal.TempFile(t, func(f *os.File) error {
				key := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqhOY9FvnDkPao59AmLDJlnPySd3FXwSXQCVzQsxpQTaTrcDH
-----END RSA PRIVATE KEY-----`
				if _, err := f.Write([]byte(key)); err != nil {
					return err
				}
				cb(f.Name())
				return nil
			})
		}, nil, fmt.Errorf("asn1: syntax error: data truncated"),
	},
	{
		func(t *testing.T, cb func(string)) error {
			return internal.TempFile(t, func(f *os.File) error {
				if _, err := f.Write([]byte(rsaTest)); err != nil {
					return err
				}
				cb(f.Name())
				return nil
			})
		}, &rsa.PrivateKey{D: rsaExp}, nil,
	},
}

func TestReadRSAKey(t *testing.T) {
	for _, entry := range entriesReadRSAKey {
		err := entry.file(t, func(path string) {
			key, err := ReadRSAKeyFromFile(path)
			if !internal.RSAEqual(key, entry.key) || !internal.ErrEqual(err, entry.err) {
				t.Errorf("ReadRSAKeyFromFile(%q) => want: %s, %s - got: %s, %s", path,
					internal.TestRSA(entry.key), internal.TestError(entry.err),
					internal.TestRSA(key), internal.TestError(err),
				)
			}
		})
		if err != nil {
			t.Fatalf("failed to create temp file")
		}
	}
}

// Generated using
// echo -n "foo"  | openssl dgst -sha256 -hmac "bar" -binary | base64
//nolint:golint,gochecknoglobals
var entriesIsSignValid = []struct {
	hash, cypher string
	key          []byte
	out          bool
}{
	{
		"FHkzIYqqvAuLEKKzpcNGhMjZQ0G88QpHNtxycPd0GFE=", "foo", []byte("bar"), true,
	},
	{
		SignEncodeBase64([]byte("foo"), []byte("bar")), "foo",
		[]byte("bar"), true,
	},
	{
		"FHkzIYqqvAuLEKKzpcNGhMjZQ0G88QpHNtxycPd0GFE=", "bar", []byte("bar"), false,
	},
	{
		SignEncodeBase64([]byte("foo"), []byte("bar")), "bar",
		[]byte("bar"), false,
	},
}

func TestIsSignValid(t *testing.T) {
	for _, entry := range entriesIsSignValid {
		out := IsSignValid(entry.hash, entry.cypher, entry.key)
		if entry.out != out {
			t.Errorf("IsSignValid(%q, %q, %q) => want: %t - got: %t",
				entry.hash, entry.cypher, entry.key, entry.out, out)
		}
	}
}

//nolint:golint,gochecknoglobals
var entriesRandString = []struct {
	reader io.Reader
	size   int
	out    string
	err    error
}{
	{strings.NewReader("foo"), 3, "Zm9v", nil},
	{strings.NewReader("foo"), 6, "Zm9vAAAA", io.ErrUnexpectedEOF},
}

func TestRandString(t *testing.T) {
	defer func() { reader = rand.Reader }() // ensure that we don't alter further tests
	for _, entry := range entriesRandString {
		buf := bytes.NewBuffer(nil)
		reader = io.TeeReader(entry.reader, buf)
		out, err := Nonce(entry.size)
		if out != entry.out || !internal.ErrEqual(err, entry.err) {
			t.Errorf("Nonce(%d) with %q => want: %q, %s - got: %q, %s",
				entry.size, buf.String(),
				entry.out, internal.TestError(entry.err), out, internal.TestError(err))
		}
	}
}
