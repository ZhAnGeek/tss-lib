// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
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
	qBytesLen := len(q.Bytes())%63 + 1 // [1,64]
	one := new(big.Int).SetInt64(1)
	for e.Cmp(q) != -1 {
		eHashAdded := auxiliary.Add(auxiliary, one)
		reSampleBytes := sha512.Sum512(append([]byte("RejectSample"), eHashAdded.Bytes()...))
		// sample qBytesLen bytes
		e = new(big.Int).SetBytes(reSampleBytes[:qBytesLen])
	}
	return e
}

type RejectionSampleFunc func(q *big.Int, eHash *big.Int) *big.Int

var RejectionSample RejectionSampleFunc = RejectionSampleV2

// RejectionSampleFixedBitLen implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSampleFixedBitLen(q *big.Int, eHash *big.Int) *big.Int {
	auxiliary := new(big.Int).Set(eHash)
	cur := new(big.Int).Set(q)
	one := new(big.Int).SetInt64(1)
	for cur.Cmp(q) != -1 || cur.Cmp(big.NewInt(0)) != 1 {
		eHashAdded := auxiliary.Add(auxiliary, one)
		eHashReSample := sha256.Sum256(eHashAdded.Bytes())
		// sample bits
		cur = new(big.Int).SetBytes(eHashReSample[:])

		// 255 - qBitLen set to 0
		for i := 255; i >= q.BitLen(); i-- {
			cur.SetBit(cur, i, 0)
		}
	}
	return cur
}

// RejectionSampleLessThanIfNecessary return val or resample val' if val >= q
// assuming val, q >= 0, q < 2^256
func RejectionSampleLessThanIfNecessary(q, val *big.Int) *big.Int {
	if val.Cmp(q) == -1 {
		return val
	}
	qBytesLen := len(q.Bytes())
	cur := val
	tag := []byte("RejectSampleLessThan#v1#")
	ctx := context.Background()

	bzs := cur.Bytes()
	for cur.Cmp(q) != -1 || cur.Cmp(big.NewInt(0)) != 1 {
		bzs = SHA512_256_TAGGED(ctx, tag, bzs)[:qBytesLen]
		cur = new(big.Int).SetBytes(bzs)
	}

	return cur
}
