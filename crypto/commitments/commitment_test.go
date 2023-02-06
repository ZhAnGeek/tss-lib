// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/Safulet/tss-lib-private/crypto/commitments"
)

func TestCreateVerify(t *testing.T) {
	ctx := context.Background()
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(ctx, zero, one)
	pass := commitment.Verify(ctx)

	assert.True(t, pass, "must pass")
}

func TestDeCommit(t *testing.T) {
	ctx := context.Background()
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(ctx, zero, one)
	pass, secrets := commitment.DeCommit(ctx, 2)

	assert.True(t, zero.Cmp(secrets[0]) == 0, "must pass")
	assert.True(t, one.Cmp(secrets[1]) == 0, "must pass")
	assert.True(t, pass, "must pass")

	assert.NotZero(t, len(secrets), "len(secrets) must be non-zero")
}
