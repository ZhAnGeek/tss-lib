// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	. "github.com/binance-chain/tss-lib/ecdsa/presigning"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	Session = []byte("session")
)

func TestMtA(test *testing.T) {
	ec := tss.EC()
	q := ec.Params().N

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(test, err, "should load keygen fixtures")
	assert.Equal(test, testThreshold+1, len(keys))
	assert.Equal(test, testThreshold+1, len(signPIDs))
	pki := keys[0].PaillierPKs[0]
	// skj := keys[1].PaillierSK
	pkj := keys[1].PaillierPKs[1]
	kj := common.GetRandomPositiveInt(q)
	Kj, err := pkj.Encrypt(kj)
	assert.NoError(test, err)

	gammai := common.GetRandomPositiveInt(q)
	BigGammai := crypto.ScalarBaseMult(ec, gammai)

	NCap, s, t, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(test, err)

	MtaOut, err := NewMtA(Session, ec, Kj, gammai, BigGammai, pkj, pki, NCap, s, t)
	assert.NoError(test, err)

	ok := MtaOut.Proofji.Verify(Session, ec, pkj, pki, NCap, s, t, Kj, MtaOut.Dji, MtaOut.Fji, BigGammai)
	assert.True(test, ok)
}
