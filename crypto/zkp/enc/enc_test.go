// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpenc_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/paillier"
	. "github.com/Safulet/tss-lib-private/v2/crypto/zkp/enc"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestEnc(test *testing.T) {
	ctx := context.Background()
	ec := tss.EC()
	q := ec.Params().N

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)

	k := common.GetRandomPositiveInt(q)
	K, rho, err := sk.EncryptAndReturnRandomness(k)
	assert.NoError(test, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(ctx, Session, ec, pk, K, NCap, s, t, k, rho, common.RejectionSample)
	assert.NoError(test, err)

	ok := proof.Verify(ctx, Session, ec, pk, NCap, s, t, K, common.RejectionSample)
	assert.True(test, ok, "proof must verify")
}

func TestEncPoc(test *testing.T) {
	ctx := context.Background()
	ec := tss.EC()
	q := ec.Params().N
	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)
	k := common.GetRandomPositiveInt(q)
	K, _, err := sk.EncryptAndReturnRandomness(k)
	assert.NoError(test, err)
	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits),
		common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	one := big.NewInt(1)
	zero := big.NewInt(0)
	proof := ProofEnc{}
	proof.S = one
	proof.A = zero
	proof.C = one
	proof.Z1 = zero
	proof.Z2 = zero
	proof.Z3 = zero
	ok := proof.Verify(ctx, Session, ec, pk, NCap, s, t, K, common.RejectionSample)
	assert.False(test, ok, "proof must verify")
}
