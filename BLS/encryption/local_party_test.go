// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package encryption

import (
	"context"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	test "github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
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
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(ePIDs)
	parties := make([]*LocalParty, 0, len(ePIDs))

	errCh := make(chan *tss.Error, len(ePIDs))
	outCh := make(chan tss.Message, len(ePIDs))
	endCh := make(chan EncryptedData, len(ePIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200)
	// init the parties
	for i := 0; i < len(ePIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, ePIDs[i], len(ePIDs), threshold, false, 0)
		P := NewLocalParty(ctx, msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
encryption:
	for {
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break encryption

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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(ePIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				break encryption
			}
		}
	}
}
