// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"github.com/Safulet/tss-lib-private/v2/common"
)

type VersionOpt func() interface{}

func NewVersion(opts ...VersionOpt) *VersionInfo {
	rejectionSampleVersion := RejectionSampleV2
	for _, opt := range opts {
		if version, ok := opt().(RejectionSampleVersion); ok {
			rejectionSampleVersion = version
		}
	}
	return &VersionInfo{rejectionSampleVersion}
}

func WithRejectionSample(version RejectionSampleVersion) VersionOpt {
	return func() interface{} {
		return version
	}
}

func GetRejectionSampleFunc(info *VersionInfo) common.RejectionSampleFunc {
	if info == nil {
		return common.RejectionSampleV2
	}
	if info.RejectionSampleVersion == RejectionSampleV1 {
		return common.RejectionSampleV1
	}
	if info.RejectionSampleVersion == RejectionSampleV2 {
		return common.RejectionSampleV2
	}
	return common.RejectionSampleV2
}
