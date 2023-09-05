// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

type RejectionSampleVersion int32

const (
	RejectionSampleV1 RejectionSampleVersion = iota
	RejectionSampleV2
)
