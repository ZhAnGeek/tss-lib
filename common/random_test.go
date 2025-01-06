// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/common"
)

const (
	randomIntBitLen = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	assert.True(t, rnd.Sign() != -1, -1, "rand int should not be negative")
	max := new(big.Int)
	max = max.Exp(big.NewInt(2), big.NewInt(int64(randomIntBitLen)), nil)
	assert.True(t, rnd.Cmp(max) == -1, -1, "rand int should not be negative")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}

func TestRandomPrime(t *testing.T) {
	rnd := common.GetRandomPrimeInt(1)
	assert.True(t, rnd == nil, "rand prime should not be 1 bit")
}

func TestGetRandomQuandraticNonResidue(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	N := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	for {
		if N.Bit(0) == 1 {
			break
		}
		N = common.GetRandomPositiveRelativelyPrimeInt(rnd)
	}
	w := common.GetRandomQuadraticNonResidue(N)
	assert.Equal(t, big.Jacobi(w, N), -1, "must get quandratic non residue")
}
