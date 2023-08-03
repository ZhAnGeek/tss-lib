// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/common"
	test "github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level log.Level) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
	tss.Bls12381()
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Bls12381(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0, nil)
		keyDerivationDelta := big.NewInt(42)
		P := NewLocalParty(ctx, msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

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
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func BenchmarkE2ESigning(b *testing.B) {
	for i := 0; i < b.N; i++ {
		E2ESigning(b)
	}
}

func E2ESigning(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	setUp(log.ErrorLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+5, testParticipants)
	assert.NoError(b, err, "should load keygen fixtures")
	assert.Equal(b, testThreshold+5, len(keys))
	assert.Equal(b, testThreshold+5, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	b.StartTimer()

	msg := big.NewInt(200).Bytes()
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Bls12381(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0, nil)
		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(ctx, msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(b, err.Error())
			break signing

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
					b.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				b.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}
