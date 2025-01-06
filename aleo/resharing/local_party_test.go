// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/aleo/signing"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

var (
	ec = tss.EdBls12377()
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(ctx, params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		P := NewLocalParty(ctx, params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
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
			if save.SkSigShare != nil {
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
					xj := key.SkSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PkSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.RSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PrSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}
				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signSaveCh := make(chan *signing.RequestOut, len(signPIDs))

	updater = test.SharedPartyUpdater

	nonce := big.NewInt(200)
	assert.NoError(t, err)
	// init the parties
	signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs signing.RInputs
	err = json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	pointUs := signing.ComputeRecordsH(signInputs)
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, signP2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		delta1 := new(big.Int).SetInt64(0)
		delta2 := new(big.Int).SetInt64(0)
		P := signing.NewLocalParty(nonce, pointUs, signInputs, params, signKeys[i], delta1, delta2, signOutCh, signSaveCh).(*signing.LocalParty)
		signParties = append(signParties, P)
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-signSaveCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)
				return
			}
		}
	}
}

func TestE2EConcurrentThresholdChange(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold, newThreshold := testThreshold, testThreshold+1

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(ctx, params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		P := NewLocalParty(ctx, params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
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
			if save.SkSigShare != nil {
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
					xj := key.SkSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PkSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.RSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PrSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}
				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signSaveCh := make(chan *signing.RequestOut, len(signPIDs))

	updater = test.SharedPartyUpdater

	nonce := big.NewInt(200)
	signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs signing.RInputs
	err = json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	pointUs := signing.ComputeRecordsH(signInputs)
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, signP2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		delta1 := new(big.Int).SetInt64(0)
		delta2 := new(big.Int).SetInt64(0)
		P := signing.NewLocalParty(nonce, pointUs, signInputs, params, signKeys[i], delta1, delta2, signOutCh, signSaveCh).(*signing.LocalParty)
		signParties = append(signParties, P)
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-signSaveCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)
				return
			}
		}
	}
}

func TestE2EConcurrentPartyChange(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants + 1)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(ctx, params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		P := NewLocalParty(ctx, params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
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
			if save.SkSigShare != nil {
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
					xj := key.SkSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PkSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.RSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PrSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}
				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signSaveCh := make(chan *signing.RequestOut, len(signPIDs))

	updater = test.SharedPartyUpdater

	nonce := big.NewInt(200)
	signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs signing.RInputs
	err = json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	pointUs := signing.ComputeRecordsH(signInputs)
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, signP2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		delta1 := new(big.Int).SetInt64(0)
		delta2 := new(big.Int).SetInt64(0)
		P := signing.NewLocalParty(nonce, pointUs, signInputs, params, signKeys[i], delta1, delta2, signOutCh, signSaveCh).(*signing.LocalParty)
		signParties = append(signParties, P)
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-signSaveCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)
				return
			}
		}
	}
}

func TestE2EConcurrentPartyThresholdChange(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold, newThreshold := testThreshold, testThreshold+1

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants + 1)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		P := NewLocalParty(ctx, params, oldKeys[j], outCh, endCh).(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold, 0)
		save := keygen.NewLocalPartySaveData(newPCount)
		P := NewLocalParty(ctx, params, save, outCh, endCh).(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
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
			if save.SkSigShare != nil {
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
					xj := key.SkSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PkSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.RSigShare
					gXj := crypto.ScalarBaseMult(ec, xj)
					BigXj := key.PrSigShares[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}
				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signSaveCh := make(chan *signing.RequestOut, len(signPIDs))

	updater = test.SharedPartyUpdater

	nonce := big.NewInt(200)
	signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs signing.RInputs
	err = json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	pointUs := signing.ComputeRecordsH(signInputs)
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, signP2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		delta1 := new(big.Int).SetInt64(0)
		delta2 := new(big.Int).SetInt64(0)
		P := signing.NewLocalParty(nonce, pointUs, signInputs, params, signKeys[i], delta1, delta2, signOutCh, signSaveCh).(*signing.LocalParty)
		signParties = append(signParties, P)
		wg.Add(1)
		go func(P *signing.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-signSaveCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)
				return
			}
		}
	}
}
