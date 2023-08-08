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
	for _, ec := range tss.GetAllCurvesList() {
		ctx := context.Background()
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
}
