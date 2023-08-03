// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpeqlog_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	"github.com/Safulet/tss-lib-private/crypto"
	. "github.com/Safulet/tss-lib-private/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/tss"
)

var (
	Session = []byte("session")
)

func TestEqLog(test *testing.T) {
	ctx := context.Background()
	ec := tss.S256()
	g, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	assert.NoError(test, err)
	h := g.ScalarMult(big.NewInt(3))
	k := big.NewInt(667767)
	x := g.ScalarMult(k)
	y := h.ScalarMult(k)

	proof, err := NewProof(ctx, Session, ec, g, h, x, y, k)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])

	ok := proof.Verify(ctx, Session, ec, g, h, x, y)
	assert.True(test, ok)

	hp := h.ScalarMult(big.NewInt(1357))
	ok = proof.Verify(ctx, Session, ec, g, hp, x, y)
	assert.False(test, ok)
}

func TestEqLogEdwards(test *testing.T) {
	ctx := context.Background()
	ec := tss.Edwards()
	g, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	assert.NoError(test, err)
	h := g.ScalarMult(big.NewInt(3))
	k := big.NewInt(667767)
	x := g.ScalarMult(k)
	y := h.ScalarMult(k)

	proof, err := NewProof(ctx, Session, ec, g, h, x, y, k)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])

	ok := proof.Verify(ctx, Session, ec, g, h, x, y)
	assert.True(test, ok)

	hp := h.ScalarMult(big.NewInt(1357))
	ok = proof.Verify(ctx, Session, ec, g, hp, x, y)
	assert.False(test, ok)
}

func TestEqLogP256(test *testing.T) {
	ctx := context.Background()
	ec := tss.P256()
	g, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	assert.NoError(test, err)
	h := g.ScalarMult(big.NewInt(3))
	k := big.NewInt(667767)
	x := g.ScalarMult(k)
	y := h.ScalarMult(k)

	proof, err := NewProof(ctx, Session, ec, g, h, x, y, k)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])

	ok := proof.Verify(ctx, Session, ec, g, h, x, y)
	assert.True(test, ok)

	hp := h.ScalarMult(big.NewInt(1357))
	ok = proof.Verify(ctx, Session, ec, g, hp, x, y)
	assert.False(test, ok)
}

func TestEqLogC25519(test *testing.T) {
	ctx := context.Background()
	ec := tss.Curve25519()
	g, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	assert.NoError(test, err)
	h := g.ScalarMult(big.NewInt(3))
	k := big.NewInt(667767)
	x := g.ScalarMult(k)
	y := h.ScalarMult(k)

	proof, err := NewProof(ctx, Session, ec, g, h, x, y, k)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])

	ok := proof.Verify(ctx, Session, ec, g, h, x, y)
	assert.True(test, ok)

	hp := h.ScalarMult(big.NewInt(1357))
	ok = proof.Verify(ctx, Session, ec, g, hp, x, y)
	assert.False(test, ok)
}

func TestEqLogBls12381(test *testing.T) {
	ctx := context.Background()
	ec := tss.Bls12381()
	g, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	assert.NoError(test, err)
	h := g.ScalarMult(big.NewInt(3))
	k := big.NewInt(667767)
	x := g.ScalarMult(k)
	y := h.ScalarMult(k)

	proof, err := NewProof(ctx, Session, ec, g, h, x, y, k)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])

	ok := proof.Verify(ctx, Session, ec, g, h, x, y)
	assert.True(test, ok)

	hp := h.ScalarMult(big.NewInt(1357))
	ok = proof.Verify(ctx, Session, ec, g, hp, x, y)
	assert.False(test, ok)
}
