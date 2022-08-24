// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmul_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	. "github.com/Safulet/tss-lib-private/crypto/zkp/mul"
	"github.com/Safulet/tss-lib-private/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestMul(test *testing.T) {
	ec := tss.EC()
	q := ec.Params().N

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)

	x := common.GetRandomPositiveInt(q)
	X, rhox, err := sk.EncryptAndReturnRandomness(x)
	assert.NoError(test, err)

	y := common.GetRandomPositiveInt(q)
	Y, _, err := sk.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)

	C, rho, err := pk.HomoMultObfuscate(x, Y)
	assert.NoError(test, err)

	proof, err := NewProof(Session, ec, pk, X, Y, C, x, rho, rhox)
	assert.NoError(test, err)

	ok := proof.Verify(Session, ec, pk, X, Y, C)
	assert.True(test, ok, "proof must verify")
}

func NewProofForged() (*ProofMul, error) {
	zero := big.NewInt(0)
	A := zero
	B := zero
	z := zero
	u := zero
	v := zero
	return &ProofMul{A: A, B: B, Z: z, U: u, V: v}, nil
}

func TestMulForged(test *testing.T) {
	ec := tss.EC()
	q := ec.Params().N
	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)
	x := common.GetRandomPositiveInt(q)
	X, _, err := sk.EncryptAndReturnRandomness(x)
	assert.NoError(test, err)
	y := common.GetRandomPositiveInt(q)
	Y, _, err := sk.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)
	C, _, err := pk.HomoMultObfuscate(x, Y)
	assert.NoError(test, err)
	// no arguments needed
	proof, err := NewProofForged()
	assert.NoError(test, err)
	ok := proof.Verify(Session, ec, pk, X, Y, C)
	assert.False(test, ok, "proof must verify")
}
