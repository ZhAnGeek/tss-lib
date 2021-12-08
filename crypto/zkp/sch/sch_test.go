// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	. "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	Session = []byte("session")
)

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	proof, _ := NewProof(Session, uG, u)

	assert.True(t, proof.A.IsOnCurve())
	assert.NotZero(t, proof.A.X())
	assert.NotZero(t, proof.A.Y())
	assert.NotZero(t, proof.Z)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewProof(Session, X, u)
	proofBz := proof.Bytes()
	proof2, _ := NewProofFromBytes(tss.EC(), proofBz[:])
	res := proof2.Verify(Session, X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofAlphaVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	alpha, A := NewAlpha(X.Curve())
	proof, _ := NewProofWithAlpha(Session, X, A, alpha, u)
	res := proof.Verify(Session, X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, _ := NewProof(Session, X2, u2)
	res := proof.Verify(Session, X)

	assert.False(t, res, "verify result must be false")
}
