// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/sha256"
	"math/big"
)

// RejectionSampleV1 implements the rejection sampling logic for converting a
// @Deprecated SHA512/256 hash to a value between 0-q
func RejectionSampleV1(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	auxiliary := new(big.Int).Set(eHash)
	e := new(big.Int).Set(q)
	one := new(big.Int).SetInt64(1)
	for e.Cmp(q) != -1 {
		eHashAdded := auxiliary.Add(auxiliary, one)
		eHashReSample := sha256.Sum256(eHashAdded.Bytes())
		// sample 32 bits
		e = new(big.Int).SetBytes(eHashReSample[:4])
	}
	return e
}

// RejectionSampleV2 implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSampleV2(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	auxiliary := new(big.Int).Set(eHash)
	e := new(big.Int).Set(q)
	qBytesLen := len(q.Bytes())
	one := new(big.Int).SetInt64(1)
	for e.Cmp(q) != -1 {
		eHashAdded := auxiliary.Add(auxiliary, one)
		eHashReSample := sha256.Sum256(eHashAdded.Bytes())
		// sample q bits
		e = new(big.Int).SetBytes(eHashReSample[:qBytesLen])
	}
	return e
}

var RejectionSample func(q *big.Int, eHash *big.Int) *big.Int = RejectionSampleV2
