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

package ykval

import (
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/bookingcom/yubistack/pkg/util"
	"github.com/bookingcom/yubistack/pkg/ykksm"
	"github.com/bookingcom/yubistack/pkg/yubico"
)

//nolint:golint,gochecknoglobals
var nonceRegex = regexp.MustCompile("^[A-Za-z0-9]{16,40}$")

// YKVal struct handles the features of the yubico YKVal module
type YKVal struct {
	zerolog.Logger
	ykksm.DecrypterFactory
	YubikeyDBMapperFactory
	Servers        []string
	SyncClientOpts []func(*SyncClient)
}

// NewYKVal creates a new instance of YKVal with sensible default
func NewYKVal(mapper YubikeyDBMapperFactory, options ...func(*YKVal)) *YKVal {
	y := &YKVal{
		Logger:                 zerolog.Nop(),
		YubikeyDBMapperFactory: mapper,
	}
	for _, option := range options {
		option(y)
	}
	return y
}

// Verify implements the Verifier interface and perform an otp validation over the network.
func (y *YKVal) Verify(req VerifyRequest) (*yubico.Yubikey, error) {
	keys := make(chan *yubico.Yubikey, len(y.Servers))
	defer close(keys)
	ytoken, ykey, err := y.Check(req)
	if err != nil {
		return nil, err
	}
	logger := y.Logger.With().Str("public", ytoken.Public).Logger()
	counter := ctr(int(req.Sl), len(y.Servers))
	if counter == 0 { // if counter is 0 no need to verify
		return ykey, nil
	}
	client := NewSyncClient(append([]func(*SyncClient){
		SyncClientTimeoutOpt(req.Timeout),
		func(sc *SyncClient) { sc.Logger = y.Logger },
		func(sc *SyncClient) { sc.SyncRequest = CreateSync(req, ykey) },
	}, y.SyncClientOpts...)...)

	logger.Info().Object("yubikey", util.YubikeyLog(*ykey)).Msg("syncing yubikey")
	wg := &sync.WaitGroup{}
	defer wg.Wait()
	wg.Add(len(y.Servers))
	for i, server := range y.Servers {
		go func(server string, _ int) {
			keys <- client.Send(server)
			wg.Done()
		}(server, i)
	}
	for i := 0; i < len(y.Servers); i++ {
		select {
		case <-client.Context().Done():
			logger.Error().Err(client.Context().Err()).Msg("failed to synchronize")
			return nil, client.Context().Err()
		case resp := <-keys:
			if resp == nil {
				continue
			}
			y.Debug().Object("yubikey", util.YubikeyLog(*resp)).Msg("handling sync response")
			if isReplayed(resp.Counter, uint(ytoken.Counter()), resp.Use, uint(ytoken.Use)) {
				logger.Warn().Msg("otp already present remotely")
				return nil, ErrReplayedOTP
			}
			if counter--; counter == 0 {
				client.Cancel()
				return ykey, nil
			}
		}
	}
	return nil, ErrNotEnoughAnswers
}

// https://developers.yubico.com/yubikey-val/Validation_Server_Algorithm.html -> 10
func isReplayed(counterOld, counterNew, useOld, useNew uint) bool {
	return counterNew < counterOld ||
		(counterNew == counterOld && useNew <= useOld)
}

func (y *YKVal) load(otp, nonce string) (*yubico.Yubikey, *yubico.Token, error) {
	ytoken, err := y.DecrypterFactory(y.Logger).Decrypt(otp)
	mapper := y.YubikeyDBMapperFactory(y.Logger)
	if err != nil {
		return nil, nil, err
	}
	logger := y.Logger.With().Str("public", ytoken.Public).Logger()
	ykey, err := mapper.YubikeyLoad(ytoken.Public)
	switch err {
	case nil:
	case ykksm.ErrNoYubikey:
		if ykey, err = mapper.YubikeyProduce(ytoken, nonce); err == nil {
			break
		}
		fallthrough
	default:
		logger.Error().Err(err).Msgf("failed to retrieve yubikey")
		return nil, nil, err
	}
	if !ykey.Active {
		logger.Warn().Msgf("yubikey not active")
		return nil, nil, ykksm.ErrNoYubikey
	}
	logger.Debug().Object("yubikey", util.YubikeyLog(*ykey)).Msg("loaded yubikey")
	return ykey, ytoken, nil
}

// Synchronize handle the synchronize request and check against internal state
func (y *YKVal) Synchronize(req SyncRequest) (*yubico.Yubikey, error) {
	mapper := y.YubikeyDBMapperFactory(y.Logger)
	ykey, _, err := y.load(req.OTP, req.Nonce)
	if err != nil {
		return nil, err
	}
	y.Debug().Msgf("request: {%s}", req)
	if ykey.Counter == req.Counter && ykey.Use == req.Use && ykey.Nonce == req.Nonce {
		y.Warn().Msg("failed to sync, potential replayed request detected")
		return nil, ErrReplayedRequest
	}
	if isReplayed(ykey.Counter, req.Counter, ykey.Use, req.Use) {
		y.Warn().Msg("failed to sync, potential replayed otp detected")
		return nil, ErrReplayedOTP
	}

	y.Info().Msgf("all checks passing for: %s", ykey.PublicName)
	return ykey, mapper.YubikeyUpdate(ykey.Clone().Update(req.Token(), req.Nonce, req.Modified))
}

// Check perform basic checks against the verify request
func (y *YKVal) Check(req VerifyRequest) (*yubico.Token, *yubico.Yubikey, error) {
	mapper := y.YubikeyDBMapperFactory(y.Logger)
	ykey, ytoken, err := y.load(req.OTP, req.Nonce)
	if err != nil {
		return nil, nil, err
	}
	logger := y.Logger.With().Str("public", ytoken.Public).Logger()
	logger.Debug().Object("token", util.TokenLog(*ytoken)).Msg("decrypted token")
	if uint(ytoken.Counter()) == ykey.Counter && uint(ytoken.Use) == ykey.Use && req.Nonce == ykey.Nonce {
		logger.Warn().Msg("replayed request")
		return nil, nil, ErrReplayedRequest
	}
	if isReplayed(ykey.Counter, uint(ytoken.Counter()), ykey.Use, uint(ytoken.Use)) {
		logger.Warn().Msg("replayed  OTP")
		return nil, nil, ErrReplayedOTP
	}
	// check for delayed, see doc for explanation, this is commented for now,
	// as it provides bad user experience
	// if y.Phishing(ytoken, ykey) {
	//	logger.Warn().Msg("delayed request")
	//	if err := mapper.YubikeyUpdate(ykey.Update(ytoken, req.Nonce, time.Now().Unix())); err != nil {
	//		y.Error().Msgf("failed to update yubikey: %s", err)
	//	}
	//	return nil, nil, ErrDelayedOTP
	// }

	logger.Debug().Msg("all check passing")
	return ytoken, ykey, mapper.YubikeyUpdate(ykey.Update(ytoken, req.Nonce, time.Now().Unix()))
}

// Phishing performs some time check in order to detect potential interception of a token
func (y *YKVal) Phishing(ytoken *yubico.Token, ykey *yubico.Yubikey) bool {
	// this implementation raises more questions than answers...
	// https://github.com/Yubico/yubikey-val/blob/a850489d245c01c0f232db56af8ff0bfaa93fb21/ykval-verify.php#L431
	// however we need to only check if counter is the same otherwise we can't rely on yubikey clock
	if uint(ytoken.Counter()) != ykey.Counter {
		return false
	}

	y.Debug().Object("yubikey", util.YubikeyTSLog(*ykey)).
		Object("token", util.TokenTSLog(*ytoken)).Msg("phishing test")
	now := time.Now().Unix()
	delta := uint(ytoken.Tstph)<<16 + uint(ytoken.Tstpl) - ykey.High<<16 - ykey.Low
	deviation := abs(now - ykey.Modified - int64(float64(delta)*KeyClockFreq))
	percentage := float64(1)
	if now-ykey.Modified != 0 {
		percentage = float64(deviation) / float64(now-ykey.Modified)
	}
	y.Debug().Uint("delta", delta).Int64("deviation", deviation).
		Float64("percentage", percentage).Msg("phishing test")
	return deviation > AbsTolerance && percentage > RelTolerance
}

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

// Compute the number of servers to reach in order to satisfy the synchronization
// level. If the value is 0 and there's at least one server we still want to
// synchronize.
func ctr(syncLvl, srvCnt int) int {
	c := srvCnt * syncLvl / 100
	if c == 0 && srvCnt > 0 {
		return 1
	}
	return c
}

// ValidateID checks the string identifier format
func ValidateID(str string) (uint64, error) {
	if str == "" {
		return 0, ErrNoID
	}
	id, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, ErrInvalidID
	}
	return id, nil
}

// ValidateNonce checks the nonce string format
func ValidateNonce(nonce string) error {
	if nonce == "" {
		return ErrNoNonce
	}
	if !nonceRegex.MatchString(nonce) {
		return ErrInvalidNonce
	}
	return nil
}

// ValidateSignature checks if the signature is valid with the given key
func ValidateSignature(hash, cipher string, key []byte) error {
	if util.IsSignValid(hash, cipher, key) {
		return nil
	}
	return ErrInvalidSignature
}
