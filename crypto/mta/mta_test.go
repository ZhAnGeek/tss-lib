// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta_test

import (
	"context"
	"testing"

	. "github.com/Safulet/tss-lib-private/v2/common"
	. "github.com/Safulet/tss-lib-private/v2/crypto"
	. "github.com/Safulet/tss-lib-private/v2/crypto/mta"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

var (
	Session = []byte("session")
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func TestMtA(test *testing.T) {
	ctx := context.Background()
	ec := tss.EC()
	q := ec.Params().N

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(test, err, "should load keygen fixtures")
	assert.Equal(test, testThreshold+1, len(keys))
	assert.Equal(test, testThreshold+1, len(signPIDs))
	pki := keys[0].PaillierPKs[0]
	// skj := keys[1].PaillierSK
	pkj := keys[1].PaillierPKs[1]
	kj := GetRandomPositiveInt(q)
	Kj, err := pkj.Encrypt(kj)
	assert.NoError(test, err)

	gammai := GetRandomPositiveInt(q)
	BigGammai := ScalarBaseMult(ec, gammai)

	NCap, s, t, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(test, err)

	MtaOut, err := NewMtA(ctx, Session, ec, Kj, gammai, BigGammai, pkj, pki, NCap, s, t, RejectionSample)
	assert.NoError(test, err)

	ok := MtaOut.Proofji.Verify(ctx, Session, ec, pkj, pki, NCap, s, t, Kj, MtaOut.Dji, MtaOut.Fji, BigGammai, RejectionSample)
	assert.True(test, ok)
}
