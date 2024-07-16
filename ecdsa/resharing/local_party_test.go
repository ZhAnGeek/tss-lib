// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen_fast"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/presigning"
	. "github.com/Safulet/tss-lib-private/v2/ecdsa/resharing"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/signing"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"github.com/stretchr/testify/assert"
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

func TestE2EConcurrentStarkCurve(t *testing.T) {
	tss.SetCurve(tss.StarkCurve())
	TestE2EConcurrent(t)
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.DebugLevel)

	// tss.SetCurve(elliptic.P256())

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	// init the new parties; re-use the fixture pre-params for speed
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + newPCount

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(tss.EC(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties
	for j, pID := range newPIDs {
		params := tss.NewReSharingParameters(tss.EC(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		if j < len(fixtures) && len(newPIDs) <= len(fixtures) {
			save.LocalPreParams = fixtures[j].LocalPreParams
		}
		P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	var wg sync.WaitGroup
	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(ctx, oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(ctx, newCommittee[destP.Index], msg, errCh)
				}
			}

		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
				newKeys[index] = *save
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				assert.Equal(t, len(oldCommittee), endedOldCommittee)
				t.Logf("Resharing done. Reshared %d participants", reSharingEnded)

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := key.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto presigning
			}
		}
	}

presigning:
	presignKeys, presignPIDs := newKeys, newPIDs
	presignP2pCtx := tss.NewPeerContext(presignPIDs)
	presignParties := make([]*presigning.LocalParty, 0, len(presignPIDs))

	presignErrCh := make(chan *tss.Error, len(presignPIDs))
	presignOutCh := make(chan tss.Message, len(presignPIDs))
	presignEndCh := make(chan *presigning.PreSignatureData, len(presignPIDs))
	presignDumpCh := make(chan *presigning.LocalDumpPB, len(presignPIDs))

	// PHASE: presigning
	for j, signPID := range presignPIDs {
		params := tss.NewParameters(tss.EC(), presignP2pCtx, signPID, len(presignPIDs), newThreshold, false, 0)
		P := presigning.NewLocalParty(params, presignKeys[j], presignOutCh, presignEndCh, presignDumpCh).(*presigning.LocalParty)
		presignParties = append(presignParties, P)
	}
	for _, party := range presignParties {
		go func(P *presigning.LocalParty) {
			if err := P.Start(ctx); err != nil {
				presignErrCh <- err
			}
		}(party)
	}
	preSigDatas := make([]*presigning.PreSignatureData, len(presignPIDs))

	var presignEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-presignErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-presignOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range presignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, presignParties[dest[0].Index], msg, errCh)
			}

		case preData := <-presignEndCh:
			atomic.AddInt32(&presignEnded, 1)
			preSigDatas[preData.UnmarshalIndex()] = preData
			t.Logf("%d ssid: %d", preData.UnmarshalIndex(), new(big.Int).SetBytes(preData.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignEnded) == int32(len(presignPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignEnded)

				goto signing
			}
		case <-presignDumpCh:
		}
	}

signing:

	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan *common.SignatureData, len(signPIDs))
	signDumpCh := make(chan *signing.LocalDumpPB, len(signPIDs))

	for j, signPID := range signPIDs {
		params := tss.NewParameters(tss.EC(), signP2pCtx, signPID, len(signPIDs), newThreshold, false, 0)
		P := signing.NewLocalParty(preSigDatas[j], big.NewInt(42), params, signKeys[j], big.NewInt(0), signOutCh, signEndCh, signDumpCh).(*signing.LocalParty)
		signParties = append(signParties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range signParties {
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				signErrCh <- err
			}
		}(party)
	}
	wg.Wait()

	var signEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, signErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, signErrCh)
			}

		case signData := <-signEndCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Signing done. Received sign data from %d participants", signEnded)

				// BEGIN ECDSA verify
				pkX, pkY := signKeys[0].ECDSAPub.X(), signKeys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(),
					new(big.Int).SetBytes(signData.R),
					new(big.Int).SetBytes(signData.S))

				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				return
			}
		case <-signDumpCh:
		}
	}
}

func TestFrostE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.DebugLevel)

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // extra can be 0 to N-first
	oldKFKeys, oldPIDs, err := keygen_fast.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	oldKeys := make([]keygen.LocalPartySaveData, len(oldKFKeys))

	for i := range oldKFKeys {
		oldKeys[i] = keygen.LocalPartySaveData{
			LocalSecrets: keygen.LocalSecrets(oldKFKeys[i].LocalSecrets),
			Ks:           oldKFKeys[i].Ks,
			BigXj:        oldKFKeys[i].BigXj,
			ECDSAPub:     oldKFKeys[i].ECDSAPub,
		}
	}

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	// init the new parties; re-use the fixture pre-params for speed
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + newPCount

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(tss.EC(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties
	for j, pID := range newPIDs {
		params := tss.NewReSharingParameters(tss.EC(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		if j < len(fixtures) && len(newPIDs) <= len(fixtures) {
			save.LocalPreParams = fixtures[j].LocalPreParams
		}
		P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	var wg sync.WaitGroup
	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(ctx, oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(ctx, newCommittee[destP.Index], msg, errCh)
				}
			}

		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
				newKeys[index] = *save
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				assert.Equal(t, len(oldCommittee), endedOldCommittee)
				t.Logf("Resharing done. Reshared %d participants", reSharingEnded)

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := key.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto presigning
			}
		}
	}

presigning:
	presignKeys, presignPIDs := newKeys, newPIDs
	presignP2pCtx := tss.NewPeerContext(presignPIDs)
	presignParties := make([]*presigning.LocalParty, 0, len(presignPIDs))

	presignErrCh := make(chan *tss.Error, len(presignPIDs))
	presignOutCh := make(chan tss.Message, len(presignPIDs))
	presignEndCh := make(chan *presigning.PreSignatureData, len(presignPIDs))
	presignDumpCh := make(chan *presigning.LocalDumpPB, len(presignPIDs))

	// PHASE: presigning
	for j, signPID := range presignPIDs {
		params := tss.NewParameters(tss.EC(), presignP2pCtx, signPID, len(presignPIDs), newThreshold, false, 0)
		P := presigning.NewLocalParty(params, presignKeys[j], presignOutCh, presignEndCh, presignDumpCh).(*presigning.LocalParty)
		presignParties = append(presignParties, P)
	}
	for _, party := range presignParties {
		go func(P *presigning.LocalParty) {
			if err := P.Start(ctx); err != nil {
				presignErrCh <- err
			}
		}(party)
	}
	preSigDatas := make([]*presigning.PreSignatureData, len(presignPIDs))

	var presignEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-presignErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-presignOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range presignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, presignParties[dest[0].Index], msg, errCh)
			}

		case preData := <-presignEndCh:
			atomic.AddInt32(&presignEnded, 1)
			preSigDatas[preData.UnmarshalIndex()] = preData
			t.Logf("%d ssid: %d", preData.UnmarshalIndex(), new(big.Int).SetBytes(preData.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignEnded) == int32(len(presignPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignEnded)

				goto signing
			}
		case <-presignDumpCh:
		}
	}

signing:

	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan *common.SignatureData, len(signPIDs))
	signDumpCh := make(chan *signing.LocalDumpPB, len(signPIDs))

	for j, signPID := range signPIDs {
		params := tss.NewParameters(tss.EC(), signP2pCtx, signPID, len(signPIDs), newThreshold, false, 0)
		P := signing.NewLocalParty(preSigDatas[j], big.NewInt(42), params, signKeys[j], big.NewInt(0), signOutCh, signEndCh, signDumpCh).(*signing.LocalParty)
		signParties = append(signParties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range signParties {
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				signErrCh <- err
			}
		}(party)
	}
	wg.Wait()
	var signEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, signErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, signErrCh)
			}

		case signData := <-signEndCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Signing done. Received sign data from %d participants", signEnded)

				// BEGIN ECDSA verify
				pkX, pkY := signKeys[0].ECDSAPub.X(), signKeys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(),
					new(big.Int).SetBytes(signData.R),
					new(big.Int).SetBytes(signData.S))

				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				return
			}
		case <-signDumpCh:
		}
	}
}
