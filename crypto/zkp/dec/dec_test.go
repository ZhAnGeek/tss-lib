// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpdec_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	. "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestDec(test *testing.T) {
	ec := tss.EC()
	q := ec.Params().N

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)

	x := common.GetRandomPositiveInt(q)
	// y := new(big.Int).Add(x, q)
	// y := common.ModInt(q).Add(x, big.NewInt(0))
	y := new(big.Int).Mod(x, q)
	C, rho, err := sk.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)

	rho2, err := sk.GetRandomness(C)
	assert.NoError(test, err)
	assert.Equal(test, 0, rho2.Cmp(rho))

	proof, err := NewProof(Session, ec, pk, C, x, NCap, s, t, y, rho2)
	assert.NoError(test, err)

	ok := proof.Verify(Session, ec, pk, C, x, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}
