// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpprm_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
)

var (
	Session = []byte("session")
)

func TestPrm(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	s, t, lambda, P, Q, N := preParams.H1i, preParams.H2i, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei
	P2, Q2 := new(big.Int).Lsh(P, 1), new(big.Int).Lsh(Q, 1)
	Phi := new(big.Int).Mul(P2, Q2)

	proof, err := NewProof(Session, s, t, N, Phi, lambda)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, s, t, N)
	assert.True(test, ok, "proof must verify")
}

// TOB-BIN-8
func TestPrmForgery(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)
	s, _, _, _, _, N := preParams.H1i, preParams.H2i, preParams.Beta, preParams.P,
		preParams.Q, preParams.NTildei
	assert.NoError(test, err)
	proofBzs := [ProofPrmBytesParts][]byte{}
	for i := 0; i < Iterations; i++ {
		buf := make([]byte, 1)
		buf[0] = 0
		proofBzs[i] = buf
	}
	for i := 0; i < Iterations; i++ {
		buf := make([]byte, 1)
		buf[0] = 1
		proofBzs[i+Iterations] = buf
	}
	proof, err := NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)
	ok := proof.Verify(Session, s, big.NewInt(0), N)
	assert.False(test, ok, "proof must verify")
}
