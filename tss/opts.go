// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"time"
)

// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

type ConfigOpt func(*Config) error

type Config struct {
	VersionInfo      *VersionInfo
	SafePrimeTimeout time.Duration
}

func NewConfig() *Config {
	return &Config{VersionInfo: NewVersion(), SafePrimeTimeout: defaultSafePrimeGenTimeout}
}

func WithRejectionSampleVersion(version RejectionSampleVersion) ConfigOpt {
	return func(config *Config) error {
		config.VersionInfo = NewVersion(WithRejectionSample(version))
		return nil
	}
}

func WithSafePrimeGenTimeout(duration time.Duration) ConfigOpt {
	return func(config *Config) error {
		config.SafePrimeTimeout = duration
		return nil
	}
}
