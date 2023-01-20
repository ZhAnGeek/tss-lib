// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmulstar_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	. "github.com/Safulet/tss-lib-private/crypto/zkp/mulstar"
	"github.com/Safulet/tss-lib-private/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestMulstar(test *testing.T) {
	ctx := context.Background()
	ec := tss.EC()
	q := ec.Params().N

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)

	x := common.GetRandomPositiveInt(q)
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	X := crypto.ScalarBaseMult(ec, x)

	y := common.GetRandomPositiveInt(q)
	C, err := sk.Encrypt(y)
	assert.NoError(test, err)

	D, rho, err := pk.HomoMultObfuscate(x, C)
	assert.NoError(test, err)

	proof, err := NewProof(ctx, Session, ec, pk, g, X, C, D, NCap, s, t, x, rho)
	assert.NoError(test, err)

	ok := proof.Verify(ctx, Session, ec, pk, g, X, C, D, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}
