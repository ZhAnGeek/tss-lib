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

	"github.com/Safulet/tss-lib-private/BLS/decryption"
	"github.com/Safulet/tss-lib-private/BLS/keygen"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/log"
	test "github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/stretchr/testify/assert"
)

var (
	suite = bls12381.GetBLSSignatureSuiteG2()
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
	setUp(log.DebugLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(ec, testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDs))

	// PHASE: signing

	encP2pCtx := tss.NewPeerContext(ePIDs)

	encErrCh := make(chan *tss.Error, len(ePIDs))
	encOutCh := make(chan tss.Message, len(ePIDs))
	encEndCh := make(chan EncryptedData, len(ePIDs))

	textOri := "Hello world 1, 2, 3, 4, 5, 6, 7"
	text := new(big.Int).SetBytes([]byte(textOri))
	msg := text.Bytes()

	// init the party
	params := tss.NewParameters(ec, encP2pCtx, ePIDs[0], 1, 1, false, 0)
	P := NewLocalParty(ctx, msg, params, keys[0], encOutCh, encEndCh).(*LocalParty)
	go func(P *LocalParty) {
		if err := P.Start(ctx); err != nil {
			encErrCh <- err
		}
	}(P)

	var cipher []byte
	var encrpytEnded int32
encryption:
	for {
		select {
		case err := <-encErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break encryption

		case <-encOutCh:
			assert.FailNow(t, "shouldn't got message for encryption")
		case data := <-encEndCh:
			atomic.AddInt32(&encrpytEnded, 1)
			cipher = data.CipherText
			t.Log("Done. Received cipher text")

			break encryption
		}
	}

	t.Log("start descryption")
	parties := make([]*decryption.LocalParty, 0, len(ePIDs))
	updater := test.SharedPartyUpdater
	decP2pCtx := tss.NewPeerContext(ePIDs)
	decErrCh := make(chan *tss.Error, len(ePIDs))
	decOutCh := make(chan tss.Message, len(ePIDs))
	decEndCh := make(chan decryption.DecryptedData, len(ePIDs))
	// init the parties
	for i := 0; i < len(ePIDs); i++ {
		params := tss.NewParameters(ec, decP2pCtx, ePIDs[i], len(ePIDs), threshold, false, 0)
		P := decryption.NewLocalParty(ctx, cipher, params, keys[i], decOutCh, decEndCh).(*decryption.LocalParty)
		parties = append(parties, P)
		go func(P *decryption.LocalParty) {
			if err := P.Start(ctx); err != nil {
				decErrCh <- err
			}
		}(P)
	}

	var ended int32
decryption:
	for {
		select {
		case err := <-decErrCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break decryption

		case msg := <-decOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, decErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, parties[dest[0].Index], msg, decErrCh)
			}

		case res := <-decEndCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(ePIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("res %v", string(res.ClearText))
				assert.Equal(t, textOri, string(res.ClearText))
				break decryption
			}
		}
	}

}
