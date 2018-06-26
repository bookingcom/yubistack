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

package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/conformal/yubikey"
	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/internal"
	"github.com/bookingcom/yubistack/pkg/ykauth"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/ykval"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

func makeCtx(query string, handler Handler) (*http.Response, error) {
	r, w := httptest.NewRequest(http.MethodGet, "/?"+query, nil), httptest.NewRecorder()
	return w.Result(), handler.Handle(&Context{Request: r, Response: NewResponse(w)})
}

func prepareAuth(query string, options ...func(*AuthHandler)) (*http.Response, error) {
	return makeCtx(query, NewAuthHandler(options...))
}

func prepareVerify(query string, options ...func(*VerifyHandler)) (*http.Response, error) {
	return makeCtx(query, NewVerifyHandler(options...))
}

func prepareSync(query string, options ...func(*SyncHandler)) (*http.Response, error) {
	return makeCtx(query, NewSyncHandler(options...))
}

func prepareDecrypt(query string, options ...func(*DecryptHandler)) (*http.Response, error) {
	return makeCtx(query, NewDecryptHandler(options...))
}

//nolint:golint,gochecknoglobals
var decryptEntries = []struct {
	prepare func() (*http.Response, error)
	want    error
}{
	{
		func() (*http.Response, error) { return prepareDecrypt("/?%gh&%ij") },
		ErrSkip,
	},
	{
		func() (*http.Response, error) {
			values := url.Values{"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}}
			return prepareDecrypt(values.Encode())
		},
		fmt.Errorf("dumb decrypter"),
	},
	{
		func() (*http.Response, error) {
			return prepareDecrypt("", func(dh *DecryptHandler) {
				dh.DecrypterFactory = func(zerolog.Logger) ykksm.Decrypter {
					return ykksm.DecrypterFunc(func(string) (*yubico.Token, error) {
						return &yubico.Token{Token: &yubikey.Token{}, Public: "foo"}, nil
					})
				}
			})
		},
		nil,
	},
}

func TestDecryptHandler(t *testing.T) {
	for _, entry := range decryptEntries {
		_, got := entry.prepare()
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("DecryptHandler().Handle() => want: %s, got: %s",
				internal.TestError(entry.want), internal.TestError(got))
		}
	}
}

// Generated using
// echo -n "counter=1&high=1&id=1&low=1&modified=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&use=1" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var syncEntries = []struct {
	prepare func() (*http.Response, error)
	want    error
}{
	{
		func() (*http.Response, error) { return prepareSync("/?%gh&%ij") },
		ErrSkip,
	},
	{
		func() (*http.Response, error) {
			values := url.Values{"counter": {"1"}}
			return prepareSync(values.Encode())
		},
		ykval.ErrNoID,
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
				"low": {"1"}, "high": {"1"}, "modified": {"1"},
				"hash": {"iW01hVERcdHiQi7Y5eYRBriWZ28qHZKlLb+Lrk232Ns="},
			}
			return prepareSync(values.Encode())
		},
		fmt.Errorf("dumb client loader"),
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
				"low": {"1"}, "high": {"1"}, "modified": {"1"},
				"hash": {"iW01hVERcdHiQi7Y5eYRBriWZ28qHZKlLb+Lrk232Ns="},
			}
			return prepareSync(values.Encode(), func(sh *SyncHandler) {
				sh.ClientLoaderFactory = clientLoaderW(
					clientLoader(&yubico.Client{Secret: "Zm9v"}, nil),
				)
			})
		},
		fmt.Errorf("dumb synchronizer"),
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "counter": {"1"}, "use": {"1"},
				"low": {"1"}, "high": {"1"}, "modified": {"1"},
				"hash": {"iW01hVERcdHiQi7Y5eYRBriWZ28qHZKlLb+Lrk232Ns="},
			}
			return prepareSync(values.Encode(), func(sh *SyncHandler) {
				sh.ClientLoaderFactory = clientLoaderW(
					clientLoader(&yubico.Client{Secret: "Zm9v"}, nil),
				)
				sh.SynchronizerFactory = synchronizer(&yubico.Yubikey{}, nil)
			})
		},
		nil,
	},
}

func TestSyncHandler(t *testing.T) {
	for _, entry := range syncEntries {
		_, got := entry.prepare()
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("SyncHandler().Handle() => want: %s, got: %s",
				internal.TestError(entry.want), internal.TestError(got))
		}
	}
}

// Generated using
// echo -n "id=1&nonce=fooooooooooooooooooo&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh" \
//    | openssl dgst -sha256 -hmac "foo" -binary | base64
//nolint:golint,gochecknoglobals
var verifyEntries = []struct {
	prepare func() (*http.Response, error)
	want    error
}{
	{
		func() (*http.Response, error) { return prepareVerify("/?%gh&%ij") },
		ErrSkip,
	},
	{
		func() (*http.Response, error) {
			values := url.Values{"timestamp": {"1"}}
			return prepareVerify(values.Encode())
		},
		ykval.ErrNoID,
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "hash": {"u62DPQSQqFvyozMmzse3Ct0Emz/JvAk/tWBFAKM6G0Y="},
			}
			return prepareVerify(values.Encode())
		},
		fmt.Errorf("dumb client loader"),
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "hash": {"u62DPQSQqFvyozMmzse3Ct0Emz/JvAk/tWBFAKM6G0Y="},
			}
			return prepareVerify(values.Encode(), func(vh *VerifyHandler) {
				vh.ClientLoaderFactory = clientLoaderW(
					clientLoader(&yubico.Client{Secret: "Zm9v"}, nil),
				)
			})
		},
		fmt.Errorf("dumb verifier"),
	},
	{
		func() (*http.Response, error) {
			values := url.Values{
				"otp": {"dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh"}, "id": {"1"},
				"nonce": {"fooooooooooooooooooo"}, "timestamp": {"1"},
				"hash": {"1NdG5Fgm3KaFyE7biKS94VqbMC+dI8ExmeWYiUNeEoE="},
			}
			return prepareVerify(values.Encode(), func(vh *VerifyHandler) {
				vh.ClientLoaderFactory = clientLoaderW(
					clientLoader(&yubico.Client{Secret: "Zm9v"}, nil),
				)
				vh.VerifierFactory = verifier(&yubico.Yubikey{}, nil)
			})
		},
		nil,
	},
}

func TestVerifyHandler(t *testing.T) {
	for _, entry := range verifyEntries {
		_, got := entry.prepare()
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("VerifyHandler().Handle() => want: %s, got: %s",
				internal.TestError(entry.want), internal.TestError(got))
		}
	}
}

//nolint:golint,gochecknoglobals
var authEntries = []struct {
	prepare func() (*http.Response, error)
	want    error
}{
	{
		func() (*http.Response, error) { return prepareAuth("/?%gh&%ij") },
		ErrSkip,
	},
	{
		func() (*http.Response, error) { return prepareAuth("") },
		fmt.Errorf("dumb authorizer"),
	},
	{
		func() (*http.Response, error) {
			values := url.Values{"password": {"foo"}}
			return prepareAuth(values.Encode(), func(ah *AuthHandler) {
				ah.AuthorizerFactory = authorizer
			})
		},
		fmt.Errorf("dumb authentifier"),
	},
	{
		func() (*http.Response, error) {
			return prepareAuth("", func(ah *AuthHandler) {
				ah.AuthorizerFactory = authorizer
			})
		},
		nil,
	},
}

func TestAuthHandler(t *testing.T) {
	for _, entry := range authEntries {
		_, got := entry.prepare()
		if !internal.ErrEqual(entry.want, got) {
			t.Errorf("AuthHandler().Handle() => want: %s, got: %s",
				internal.TestError(entry.want), internal.TestError(got))
		}
	}
}

/* -------------------------------------------------------------------------- */
/* ---------           Bunch of helpers for those testing           --------- */
/* -------------------------------------------------------------------------- */

//nolint:golint,unparam
func clientLoader(client *yubico.Client, err error) yubico.ClientLoader {
	return yubico.ClientLoaderFunc(func(uint64) (*yubico.Client, error) { return client, err })
}

func clientLoaderW(cl yubico.ClientLoader) func(zerolog.Logger) yubico.ClientLoader {
	return func(zerolog.Logger) yubico.ClientLoader { return cl }
}

func synchronizer(key *yubico.Yubikey, err error) ykval.SynchronizerFactory {
	return func(zerolog.Logger) ykval.Synchronizer {
		return ykval.SynchronizerFunc(func(ykval.SyncRequest) (*yubico.Yubikey, error) {
			return key, err
		})
	}
}

func verifier(key *yubico.Yubikey, err error) ykval.VerifierFactory {
	return func(zerolog.Logger) ykval.Verifier {
		return ykval.VerifierFunc(func(ykval.VerifyRequest) (*yubico.Yubikey, error) {
			return key, err
		})
	}
}

//nolint:golint,gochecknoglobals
var authorizer = func(zerolog.Logger) ykauth.Authorizer {
	return ykauth.AuthorizerFunc(func(string, string) error { return nil })
}
