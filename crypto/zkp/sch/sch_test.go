// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	. "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

var (
	Session = []byte("session")
)

func TestSchnorrProof(t *testing.T) {
	ctx := context.Background()
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	rejectionSample := tss.GetRejectionSampleFunc(nil)
	proof, _ := NewProof(ctx, Session, uG, u, rejectionSample)

	assert.True(t, proof.A.IsOnCurve())
	assert.NotZero(t, proof.A.X())
	assert.NotZero(t, proof.A.Y())
	assert.NotZero(t, proof.Z)
}

func TestSchnorrProofVerify(t *testing.T) {
	ctx := context.Background()
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	rejectionSample := tss.GetRejectionSampleFunc(nil)
	proof, _ := NewProof(ctx, Session, X, u, rejectionSample)
	proofBz := proof.Bytes()
	proof2, _ := NewProofFromBytes(tss.EC(), proofBz[:])
	res := proof2.Verify(ctx, Session, X, rejectionSample)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofAlphaVerify(t *testing.T) {
	ctx := context.Background()
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	alpha, A := NewAlpha(X.Curve())
	rejectionSample := tss.GetRejectionSampleFunc(nil)
	proof, _ := NewProofWithAlpha(ctx, Session, X, A, alpha, u, rejectionSample)
	res := proof.Verify(ctx, Session, X, rejectionSample)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	ctx := context.Background()
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	rejectionSample := tss.GetRejectionSampleFunc(nil)
	proof, _ := NewProof(ctx, Session, X2, u2, rejectionSample)
	res := proof.Verify(ctx, Session, X, rejectionSample)

	assert.False(t, res, "verify result must be false")
}
