// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold
)

func setUp(level log.Level) {
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
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		params.SetIsSchnorr()
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
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
	wg.Add(3 * len(pIDs) * (len(pIDs) - 1))
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

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						// vssMsgs := P.temp.kgRound2Message1s
						// share := vssMsgs[j].Content().(*KGRound2Message1).Share
						share := P.temp.r2msg1Shares[j]
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							// Share:     new(big.Int).SetBytes(share),
							Share: new(big.Int).SetBytes(share.Bytes()),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.S256(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.S256(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.S256().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}
				u = new(big.Int).Mod(u, tss.S256().Params().N)
				pkX, pkY := save.PubKey.X(), save.PubKey.Y()

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.S256().ScalarBaseMult(u.Bytes())
				if ourPkY.Bit(0) != 0 {
					ourPkY = new(big.Int).Sub(tss.S256().Params().P, ourPkY)
				}
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same Schnorr public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.PubKey.X())
					assert.Equal(t, pkY, Pj.data.PubKey.Y())
				}
				t.Log("Public key distribution test done.")
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func TestE2EConcurrentAndSaveFixturesNonSchnorr(t *testing.T) {
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
		var P *LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
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
	wg.Add(3 * len(pIDs) * (len(pIDs) - 1))
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

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						// vssMsgs := P.temp.kgRound2Message1s
						// share := vssMsgs[j].Content().(*KGRound2Message1).Share
						share := P.temp.r2msg1Shares[j]
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							// Share:     new(big.Int).SetBytes(share),
							Share: new(big.Int).SetBytes(share.Bytes()),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.Edwards())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.Edwards(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.Edwards(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.Edwards())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.Edwards().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}
				u = new(big.Int).Mod(u, tss.Edwards().Params().N)
				pkX, pkY := save.PubKey.X(), save.PubKey.Y()

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.Edwards().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same Schnorr public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.PubKey.X())
					assert.Equal(t, pkY, Pj.data.PubKey.Y())
				}
				t.Log("Public key distribution test done.")
				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func TestE2EConcurrentAndSaveFixturesWithPallas(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)
	curve := tss.Pallas()

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixturesWithCurve(testParticipants, curve)
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
		var P *LocalParty
		params := tss.NewParameters(curve, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		params.SetIsSchnorr()
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
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
	wg.Add(3 * len(pIDs) * (len(pIDs) - 1))
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
			tryWriteTestFixtureFileWithCurve(t, index, *save, curve)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				wg.Wait()
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						// vssMsgs := P.temp.kgRound2Message1s
						// share := vssMsgs[j].Content().(*KGRound2Message1).Share
						share := P.temp.r2msg1Shares[j]
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							// Share:     new(big.Int).SetBytes(share),
							Share: new(big.Int).SetBytes(share.Bytes()),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(curve)
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(curve, uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(curve, xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(curve)
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := curve.ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}
				u = new(big.Int).Mod(u, curve.Params().N)
				pkX, pkY := save.PubKey.X(), save.PubKey.Y()

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := curve.ScalarBaseMult(u.Bytes())
				if ourPkY.Bit(0) != 0 {
					ourPkY = new(big.Int).Sub(curve.Params().P, ourPkY)
				}
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same Schnorr public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.PubKey.X())
					assert.Equal(t, pkY, Pj.data.PubKey.Y())
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

func tryWriteTestFixtureFileWithCurve(t *testing.T, index int, data LocalPartySaveData, curve elliptic.Curve) {
	fixtureFileName := makeTestFixtureFilePathWithCurve(index, curve)

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