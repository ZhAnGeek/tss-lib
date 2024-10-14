// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform_test

import (
	"context"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keyshare_affine_transform"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/utils"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestE2ETransformKeyShares(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	ec := tss.S256()
	threshold := testThreshold
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		log.Info(ctx, "No test keys were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keyshare_affine_transform.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	A := big.NewInt(3)
	B := big.NewInt(2)
	keyDerivationDelta := big.NewInt(121)
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P := keyshare_affine_transform.NewLocalParty(params, keys[i], keyDerivationDelta, A, B, outCh, endCh).(*keyshare_affine_transform.LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *keyshare_affine_transform.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	transformedKeys := make([]keygen.LocalPartySaveData, testParticipants)
	// PHASE: keytransform
	var ended int32
keytransform:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break keytransform

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			transformedKeys[index] = *save

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				tsk, err := utils.RestoreECDSAPrivateKey(ec, threshold, transformedKeys)
				assert.NoError(t, err)
				// check tsk == csk * A + B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				rhs := modN.Mul(csk, A)
				rhs = modN.Add(rhs, B)
				assert.Zero(t, rhs.Cmp(tsk.SK()))

				break keytransform
			}
		}
	}
}

func TestE2ETransformKeySharesCKD(t *testing.T) {
	var res0 *crypto.ECPoint
	ctx := context.Background()
	setUp(log.InfoLevel)

	ec := tss.S256()
	threshold := testThreshold
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		log.Info(ctx, "No test keys were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keyshare_affine_transform.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	A := big.NewInt(3)
	B := big.NewInt(2)
	keyDerivationDelta := big.NewInt(0)
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P := keyshare_affine_transform.NewLocalParty(params, keys[i], keyDerivationDelta, A, B, outCh, endCh).(*keyshare_affine_transform.LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *keyshare_affine_transform.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	transformedKeys := make([]keygen.LocalPartySaveData, testParticipants)
	// PHASE: keytransform
	var ended int32
keytransform:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break keytransform

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			transformedKeys[index] = *save

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				tsk, err := utils.RestoreECDSAPrivateKey(ec, threshold, transformedKeys)
				assert.NoError(t, err)
				// check tsk == csk * A + B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				rhs := modN.Mul(csk, A)
				rhs = modN.Add(rhs, B)
				assert.Zero(t, rhs.Cmp(tsk.SK()))

				res0 = transformedKeys[0].ECDSAPub
				break keytransform
			}
		}
	}

	var res1 *crypto.ECPoint
	p2pCtx = tss.NewPeerContext(pIDs)
	parties = make([]*keyshare_affine_transform.LocalParty, 0, len(pIDs))

	errCh = make(chan *tss.Error, len(pIDs))
	outCh = make(chan tss.Message, len(pIDs))
	endCh = make(chan *keygen.LocalPartySaveData, len(pIDs))

	// init the parties
	keyDerivationDelta = big.NewInt(123)
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P := keyshare_affine_transform.NewLocalParty(params, keys[i], keyDerivationDelta, A, B, outCh, endCh).(*keyshare_affine_transform.LocalParty)
		parties = append(parties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range parties {
		wg.Add(1)
		go func(P *keyshare_affine_transform.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	transformedKeys = make([]keygen.LocalPartySaveData, testParticipants)
	// PHASE: keytransform
	ended = int32(0)
keytransform1:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break keytransform1

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			transformedKeys[index] = *save

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				tsk, err := utils.RestoreECDSAPrivateKey(ec, threshold, transformedKeys)
				assert.NoError(t, err)
				// check tsk == csk * A + B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				rhs := modN.Mul(csk, A)
				rhs = modN.Add(rhs, B)
				assert.Zero(t, rhs.Cmp(tsk.SK()))

				res1 = transformedKeys[0].ECDSAPub
				break keytransform1
			}
		}
	}
	// res0 = (a * x + b) * G
	// res1 = (a * (x + delta) + b) * G = res0 + a * delta * G
	adG := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	assert.NotNil(t, adG)
	adG = adG.ScalarMult(A)
	assert.NotNil(t, adG)
	res2, err := res0.Add(adG)
	assert.NoError(t, err)
	fmt.Println("res1: ", res1.X(), res1.Y())
	fmt.Println("res2: ", res2.X(), res2.Y())
	assert.True(t, res1.Equals(res2))
}
