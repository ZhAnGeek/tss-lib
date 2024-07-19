// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"fmt"
	"hash"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/crypto"

	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
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

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)
	ec := tss.Edwards()

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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	keyDerivationDelta, ok := new(big.Int).SetString("999797428896018067204024566940022162647215160545998861444590892633251233502", 10)
	assert.True(t, ok)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
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
				R := parties[0].temp.r

				// BEGIN check s correctness
				modQ := common.ModInt(ec.Params().N)
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					sumS = modQ.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				PKX, PKY := keys[0].EDDSAPub.X(), keys[1].EDDSAPub.Y()
				if keyDerivationDelta.Cmp(zero) != 0 {
					DeltaX, DeltaY := ec.ScalarBaseMult(keyDerivationDelta.Bytes())
					PKX, PKY = ec.Add(PKX, PKY, DeltaX, DeltaY)
				}

				pk, err := crypto.NewECPoint(ec, PKX, PKY)
				if err != nil {
					println("construct public key error, ", err.Error())
				}
				sigR := new(big.Int).SetBytes(parties[0].data.R)
				sigS := new(big.Int).SetBytes(parties[0].data.S)
				ok := VerifyEdwards(pk, msg, sigR, sigS, parties[0].params.HashFunc)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}

func TestEE2EConcurrentBlake2b(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)
	ec := tss.Edwards()

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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	keyDerivationDelta := big.NewInt(666777)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetHashFunc(func() hash.Hash {
			hasher, _ := blake2b.New512(nil)
			return hasher
		})
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
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
				R := parties[0].temp.r
				// BEGIN check s correctness
				modQ := common.ModInt(ec.Params().N)
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}
					sumS = modQ.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", sumS.String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness
				// BEGIN EDDSA verify
				PKX, PKY := keys[0].EDDSAPub.X(), keys[1].EDDSAPub.Y()
				if keyDerivationDelta.Cmp(zero) != 0 {
					DeltaX, DeltaY := ec.ScalarBaseMult(keyDerivationDelta.Bytes())
					PKX, PKY = ec.Add(PKX, PKY, DeltaX, DeltaY)
				}

				pk, err := crypto.NewECPoint(ec, PKX, PKY)
				if err != nil {
					println("construct public key error, ", err.Error())
				}
				sigR := new(big.Int).SetBytes(parties[0].data.R)
				sigS := new(big.Int).SetBytes(parties[0].data.S)
				ok := VerifyEdwards(pk, msg, sigR, sigS, parties[0].params.HashFunc)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify
				break signing
			}
		}
	}
}
