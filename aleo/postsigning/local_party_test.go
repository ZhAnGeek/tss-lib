// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postsigning_test

import (
	"context"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/aleo/postsigning"
	"github.com/Safulet/tss-lib-private/v2/aleo/signing"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testThreshold = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.DebugLevel)
	ec := tss.EdBls12377()

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, psignPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1) // , testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(psignPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(psignPIDs)
	parties := make([]*postsigning.LocalParty, 0, len(psignPIDs))

	errCh := make(chan *tss.Error, len(psignPIDs))
	outCh := make(chan tss.Message, len(psignPIDs))
	endCh := make(chan *postsigning.RequestData, len(psignPIDs))

	updater := test.SharedPartyUpdater

	signDatas := make([]*signing.SignData, len(keys))
	ssid, _ := new(big.Int).SetString("111727040389651131380210699229022162484532906382920465169380070271745624941637", 10)
	ri, _ := new(big.Int).SetString("1580604604829946753955147776861437800835808308485989539198687491355116880085", 10)
	signDatas[0] = signing.NewSignData(ssid.Bytes(), ri)
	ri, _ = new(big.Int).SetString("209788796287442200433719431621208871030822193668729160499214078536591835840", 10)
	signDatas[1] = signing.NewSignData(ssid.Bytes(), ri)

	challenge, _ := new(big.Int).SetString("749788630801425165281121861901784471075263365650076418459635487582516611289", 10)

	// init the parties
	nonce := big.NewInt(200)
	wg := sync.WaitGroup{}
	for i := 0; i < len(psignPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, psignPIDs[i], len(psignPIDs), threshold, false, 0)

		delta := big.NewInt(42)
		P := postsigning.NewLocalParty(nonce, challenge, signDatas[i], params, keys[i], delta, outCh, endCh).(*postsigning.LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *postsigning.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
postsigning:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break postsigning

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
			if atomic.LoadInt32(&ended) == int32(len(psignPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break postsigning
			}
		}
	}
}
