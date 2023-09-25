// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"context"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/log"
	test "github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/stretchr/testify/assert"
)

var (
	suite = bls12381.GetBLSSignatureSuiteG1()
	ec    = tss.GetBLSCurveBySuite(suite)
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level log.Level) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
	tss.Bls12381G2()
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, ePIDS, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDS))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(ePIDS)
	parties := make([]*LocalParty, 0, len(ePIDS))

	errCh := make(chan *tss.Error, len(ePIDS))
	outCh := make(chan tss.Message, len(ePIDS))
	endCh := make(chan DecryptedData, len(ePIDS))

	updater := test.SharedPartyUpdater

	textOri := "Hello world 1, 2, 3, 4, 5, 6, 7"
	text := new(big.Int).SetBytes([]byte(textOri))
	msg, err := crypto.BLSEncryptByECPoint(suite, keys[0].PubKey, text.Bytes())
	if err != nil {
		t.FailNow()
	}

	// init the parties
	for i := 0; i < len(ePIDS); i++ {
		params := tss.NewParameters(ec, p2pCtx, ePIDS[i], len(ePIDS), threshold, false, 0)
		P := NewLocalParty(ctx, msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
decryption:
	for {
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break decryption

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case res := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(ePIDS)) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("res %v", new(big.Int).SetBytes(res.ClearText))
				assert.Equal(t, textOri, string(res.ClearText))
				break decryption
			}
		}
	}
}