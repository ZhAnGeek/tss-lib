// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package shared_secret_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/shared_secret"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/utils"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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

func TestE2ESharedSecrets(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold
	ec := tss.S256()
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(testParticipants)
	// keys, pIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*shared_secret.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *crypto.ECPoint, len(pIDs))

	updater := test.SharedPartyUpdater

	b := big.NewInt(12345)
	B := crypto.ScalarBaseMult(ec, b)
	keyDerivationDelta := big.NewInt(119)
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *shared_secret.LocalParty
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P = shared_secret.NewLocalParty(B, params, keys[i], keyDerivationDelta, outCh, endCh).(*shared_secret.LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *shared_secret.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	// PHASE: interaction
	var ended int32
interaction:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break interaction

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

		case result := <-endCh:

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				// shared secret is (sk + delta) * b * G = b * ChildPK = (sk + delta) * B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				ab := modN.Mul(csk, b)
				Ref := crypto.ScalarBaseMult(ec, ab)
				assert.True(t, Ref.Equals(result), "should compute csk * b * G")

				break interaction
			}
		}
	}
}

func TestE2ESharedSecretsCKD(t *testing.T) {
	var res0 *crypto.ECPoint

	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold
	ec := tss.S256()
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(testParticipants)
	// keys, pIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*shared_secret.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *crypto.ECPoint, len(pIDs))

	updater := test.SharedPartyUpdater

	b := big.NewInt(12345)
	B := crypto.ScalarBaseMult(ec, b)
	keyDerivationDelta := big.NewInt(0)
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *shared_secret.LocalParty
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P = shared_secret.NewLocalParty(B, params, keys[i], keyDerivationDelta, outCh, endCh).(*shared_secret.LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *shared_secret.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	// PHASE: interaction
	var ended int32
interaction:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break interaction

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

		case result := <-endCh:

			atomic.AddInt32(&ended, 1)
			if res0 == nil {
				res0 = result
			} else {
				assert.True(t, res0.Equals(result), "should compute same result")
			}
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				// shared secret is (sk + delta) * b * G = b * ChildPK = (sk + delta) * B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				ab := modN.Mul(csk, b)
				Ref := crypto.ScalarBaseMult(ec, ab)
				assert.True(t, Ref.Equals(result), "should compute csk * b * G")

				break interaction
			}
		}
	}
	fmt.Println("####### res0:", res0.X().String(), res0.Y().String())

	var res1 *crypto.ECPoint

	p2pCtx = tss.NewPeerContext(pIDs)
	parties = make([]*shared_secret.LocalParty, 0, len(pIDs))

	errCh = make(chan *tss.Error, len(pIDs))
	outCh = make(chan tss.Message, len(pIDs))
	endCh = make(chan *crypto.ECPoint, len(pIDs))

	keyDerivationDelta = big.NewInt(123)
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *shared_secret.LocalParty
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P = shared_secret.NewLocalParty(B, params, keys[i], keyDerivationDelta, outCh, endCh).(*shared_secret.LocalParty)
		parties = append(parties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range parties {
		wg.Add(1)
		go func(P *shared_secret.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	// PHASE: interaction
	ended = int32(0)
interaction1:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break interaction1

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

		case result := <-endCh:

			atomic.AddInt32(&ended, 1)
			if res1 == nil {
				res1 = result
			} else {
				assert.True(t, res1.Equals(result), "should compute same result")
			}
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				// shared secret is (sk + delta) * b * G = b * ChildPK = (sk + delta) * B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				ab := modN.Mul(csk, b)
				Ref := crypto.ScalarBaseMult(ec, ab)
				assert.True(t, Ref.Equals(result), "should compute csk * b * G")

				break interaction1
			}
		}
	}
	fmt.Println("####### res1:", res1.X().String(), res1.Y().String())
	// res0 = sk * B
	// res1 = csk * B = (sk + delta) * B = res0 + delta * B
	deltaB := B.ScalarMult(keyDerivationDelta)
	res2, err := res0.Add(deltaB)
	assert.NoError(t, err)
	fmt.Println("####### res2:", res2.X().String(), res2.Y().String())
	assert.True(t, res1.Equals(res2), "should equal from both side")
}

func ecdh(a *big.Int, B *crypto.ECPoint) *crypto.ECPoint {
	abG := B.ScalarMult(a)
	return abG
}

func TestFoo(t *testing.T) {
	ec := tss.S256()
	b, ok := new(big.Int).SetString("c15c35c99399bcea0a3b6df7e70970cac9a70048aa964252b90a12595a4612f5", 16)
	assert.True(t, ok)
	B := crypto.ScalarBaseMult(ec, b)
	fmt.Println("b: ", hex.EncodeToString(b.Bytes()))
	fmt.Println("B: ", hex.EncodeToString(secp256k1.CompressPubkey(B.X(), B.Y())))

	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(testParticipants)
	// keys, pIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	if err != nil {
		log.Info(ctx, "No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*shared_secret.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *crypto.ECPoint, len(pIDs))

	updater := test.SharedPartyUpdater

	keyDerivationDelta := big.NewInt(12345)
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *shared_secret.LocalParty
		params := tss.NewParameters(ec, p2pCtx, pIDs[i], len(pIDs), threshold, false, 0)
		P = shared_secret.NewLocalParty(B, params, keys[i], keyDerivationDelta, outCh, endCh).(*shared_secret.LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *shared_secret.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	// PHASE: interaction
	var ended int32
interaction:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break interaction

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

		case result := <-endCh:

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// compute the shared secret from raw secret key
				sk, err := utils.RestoreECDSAPrivateKey(ec, threshold, keys)
				assert.NoError(t, err)
				// shared secret is (sk + delta) * b * G = b * ChildPK = (sk + delta) * B
				modN := common.ModInt(ec.Params().N)
				csk := modN.Add(sk.SK(), keyDerivationDelta)
				Ref := ecdh(csk, B)
				assert.True(t, Ref.Equals(result), "should compute csk * b * G")

				ckeys, err := utils.ApplyDeltaToECDSALocalPartySaveData(ec, threshold, keys, keyDerivationDelta)
				cPK := ckeys[0].ECDSAPub
				Ref2 := ecdh(b, cPK)
				assert.True(t, Ref2.Equals(result), "should compute csk * b * G")

				break interaction
			}
		}
	}

}
