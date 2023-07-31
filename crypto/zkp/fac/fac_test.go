// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpfac_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	. "github.com/Safulet/tss-lib-private/crypto/zkp/fac"
	"github.com/Safulet/tss-lib-private/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestFac(test *testing.T) {
	ctx := context.Background()
	ec := tss.EC()

	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(ctx, Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok := proof.Verify(ctx, Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

	N0p = common.GetRandomPrimeInt(1024)
	N0q = common.GetRandomPrimeInt(1024)
	N0 = new(big.Int).Mul(N0p, N0q)

	proof, err = NewProof(ctx, Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok = proof.Verify(ctx, Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

	// factor should have bits [1024-16, 1024+16]
	smallFactor := 900
	N0p = common.GetRandomPrimeInt(smallFactor)
	N0q = common.GetRandomPrimeInt(2048 - smallFactor)
	N0 = new(big.Int).Mul(N0p, N0q)

	proof, err = NewProof(ctx, Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok = proof.Verify(ctx, Session, ec, N0, NCap, s, t)
	assert.False(test, ok, "proof must not verify")
}
