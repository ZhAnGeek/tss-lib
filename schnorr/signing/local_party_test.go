// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"fmt"
	"github.com/Safulet/tss-lib-private/crypto/ckd"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/schnorr/keygen"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
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

func BenchmarkE2E(b *testing.B) {
	for i := 0; i < b.N; i++ {
		E2E(b)
	}
}

func E2E(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	setUp(log.ErrorLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, _ := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}

	b.StartTimer()
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		select {
		case <-errCh:
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
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}
		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

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
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// compute child key delta
	testMasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	pkExt, err := ckd.NewExtendedKeyFromString(testMasterPubKey, tss.S256())
	assert.NoError(t, err)
	pkNew := keys[0].PubKey
	pkExt.PublicKey = *pkNew
	path := []uint32{0, 1, 2, 2}
	ec := tss.S256()
	delta, childExtKey, err := ckd.DeriveChildKeyFromHierarchy(ctx, path, pkExt, ec.Params().N, ec)
	assert.NoError(t, err)
	assert.False(t, delta.Uint64() == 0, "delta is not zero")
	assert.True(t, childExtKey.PublicKey.IsOnCurve())

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		keyDerivationDelta := delta
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func TestE2EConcurrentFromECDSA(t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesFromECDSA(2)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func BenchmarkE2EMina(b *testing.B) {
	for i := 0; i < b.N; i++ {
		E2EMina(b)
	}
}

func E2EMina(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	curve := tss.Pallas()
	setUp(log.ErrorLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, _ := keygen.LoadKeygenTestFixturesRandomSetWithCurve(testThreshold+1, curve, testParticipants)

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}

	b.StartTimer()
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(curve, p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetNetwork(tss.MINA)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		select {
		case <-errCh:
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
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}
		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
}

func TestE2EConcurrentMina(t *testing.T) {
	ctx := context.Background()

	threshold := testThreshold
	curve := tss.Pallas()
	setUp(log.InfoLevel)

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSetWithCurve(testThreshold+1, curve, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// compute child key delta
	testMasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	pkExt, err := ckd.NewExtendedKeyFromString(testMasterPubKey, tss.S256())
	assert.NoError(t, err)
	pkNew := keys[0].PubKey
	pkExt.PublicKey = *pkNew
	path := []uint32{0, 1, 2, 2}
	delta, childExtKey, err := ckd.DeriveChildKeyFromHierarchy(ctx, path, pkExt, curve.Params().N, curve)
	assert.NoError(t, err)
	assert.False(t, delta.Uint64() == 0, "delta is not zero")
	assert.True(t, childExtKey.PublicKey.IsOnCurve())

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(curve, p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetNetwork(tss.MINA)

		keyDerivationDelta := delta
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func BenchmarkE2EZil(b *testing.B) {
	for i := 0; i < b.N; i++ {
		E2EZil(b)
	}
}

func E2EZil(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	setUp(log.ErrorLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, _ := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}

	b.StartTimer()
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetNetwork(tss.ZIL)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		select {
		case <-errCh:
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
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}
		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
}

func TestE2EConcurrentZil(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

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
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetNetwork(tss.ZIL)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func TestE2EConcurrentFromECDSAZil(t *testing.T) {
	ctx := context.Background()
	setUp(log.InfoLevel)

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesFromECDSA(2)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		params.SetNetwork(tss.ZIL)

		keyDerivationDelta := big.NewInt(10)
		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(P)
	}
	wg.Wait()

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
				// already verified in finalize.go
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}
