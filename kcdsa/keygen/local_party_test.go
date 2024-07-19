// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdaterWithWg

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var localPreParams, generateErr = GeneratePreParams(ctx, time.Minute*5)
		assert.NoError(t, generateErr)

		var P *LocalParty
		params := tss.NewParameters(tss.Curve25519(), p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, *localPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh, *localPreParams).(*LocalParty)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
	wg := sync.WaitGroup{}
	// P2P rounds 3, Broadcast rounds 2
	wg.Add(5 * len(pIDs) * (len(pIDs) - 1))
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh, &wg)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh, &wg)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, *save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				wg.Wait()
				t.Logf("Done. Received save data from %d participants", ended)

				// combine vs_xshares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						// vssMsgs := P.temp.kgRound2Message1s
						// share := vssMsgs[j].Content().(*KGRound2Message1).Share
						share := P.temp.r2msg1SharesX[j]
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							// Share:     new(big.Int).SetBytes(share),
							Share: new(big.Int).SetBytes(share.Bytes()),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.Curve25519())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.Curve25519(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// no need to check this
					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.Curve25519(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.Curve25519())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.Curve25519().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}
				u = new(big.Int).Mod(u, tss.Curve25519().Params().N)
				pkg := save.PubKey.ScalarMult(u)
				pkX, pkY := pkg.X(), pkg.Y()

				needsNeg := pkg.Y().Bit(0) != 1
				if needsNeg {
					Y2 := new(big.Int).Sub(tss.Curve25519().Params().P, pkg.Y())
					if err != nil {
						panic(err)
					}
					pkY = Y2
				}

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.Curve25519().Params().Gx, tss.Curve25519().Params().Gy
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same KCDSA public key
				for _, Pj := range parties {
					pkg := Pj.data.PubKey.ScalarMult(u)
					pkX, pkY := pkg.X(), pkg.Y()
					needsNeg := pkg.Y().Bit(0) != 1
					if needsNeg {
						Y2 := new(big.Int).Sub(tss.Curve25519().Params().P, pkg.Y())
						if err != nil {
							panic(err)
						}
						pkY = Y2
					}
					assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
					assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				}
				t.Log("Public key distribution test done.")
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	dir := path.Dir(fixtureFileName)
	os.MkdirAll(dir, 0751)
	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
