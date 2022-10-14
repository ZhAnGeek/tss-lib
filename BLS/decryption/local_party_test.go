// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/ipfs/go-log/v2"
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

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
	tss.Bls12381()
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

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

	totalPK := make([]byte, 192)
	copy(totalPK[:96], keys[0].PubKey.X().Bytes())
	copy(totalPK[96:], keys[0].PubKey.Y().Bytes())
	text := new(big.Int).SetBytes([]byte("Hello World World World World"))
	msg, err := bls12381.Encrypt(totalPK, text.Bytes())
	if err != nil {
		t.FailNow()
	}

	// init the parties
	for i := 0; i < len(ePIDS); i++ {
		params := tss.NewParameters(tss.Bls12381(), p2pCtx, ePIDS[i], len(ePIDS), threshold, false, 0)
		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
decryption:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break decryption

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case res := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(ePIDS)) {
				t.Logf("Done. Received save data from %d participants", ended)
				t.Logf("res %v", new(big.Int).SetBytes(res.ClearText))
				assert.Equal(t, string(res.ClearText), "Hello World World World World")
				break decryption
			}
		}
	}
}
