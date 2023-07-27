// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/armfazh/h2c-go-ref"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	testParticipants            = test.TestParticipants
	testThreshold               = test.TestThreshold
	testFixtureDirFormatECDSA   = "%s/../test/_ecdsa_fixtures_%d_%d"
	testFixtureDirFormatEDDSA   = "%s/../test/_eddsa_fixtures_%d_%d"
	testFixtureDirFormatSCHNORR = "%s/../test/_schnorr_fixtures_%d_%d"
	testFixtureFileFormat       = "keygen_data_%d.json"
)

func setUp(level log.Level) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func makeTestFixtureFilePath(partyIndex int, fixtureBase string) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(fixtureBase, srcDirName, testThreshold, testParticipants)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func TestH2C(t *testing.T) {
	dst := "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
	hashToCurve, err := h2c.Secp256k1_XMDSHA256_SSWU_RO_.Get([]byte(dst))
	assert.NoError(t, err, "should init h2c")
	h2cPoint := hashToCurve.Hash([]byte("abc"))
	h2cPx := h2cPoint.X().Polynomial()[0]
	h2cPy := h2cPoint.Y().Polynomial()[0]
	fmt.Println("x:", fmt.Sprintf("0x%x", h2cPx))
	fmt.Println("y:", fmt.Sprintf("0x%x", h2cPy))
	_, err = crypto.NewECPoint(tss.S256(), h2cPx, h2cPy)
	assert.NoError(t, err, "should hash to curve")
}

func TestE2EConcurrentFromECDSA(t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

	// PHASE: load keygen fixtures
	keys, derivekeyPIDs, err := LoadKeygenTestFixtures(testThreshold+1, testFixtureDirFormatECDSA) // 0 -- testParticipants-testThreshold-1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(derivekeyPIDs))

	// PHASE: deriveChildKey

	p2pCtx := tss.NewPeerContext(derivekeyPIDs)
	parties := make([]*LocalParty, 0, len(derivekeyPIDs))

	errCh := make(chan *tss.Error, len(derivekeyPIDs))
	outCh := make(chan tss.Message, len(derivekeyPIDs))
	// endCh := make(chan common.SignatureData, len(derivekeyPIDs))
	endCh := make(chan tss.Message, len(derivekeyPIDs))

	updater := test.SharedPartyUpdater

	path := []byte("/6667'/")
	chainCode := []byte("testChainCodeABC")
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(derivekeyPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, derivekeyPIDs[i], len(derivekeyPIDs), testThreshold, false, 0)

		P := NewLocalParty(path, chainCode, params, keys[i], outCh, endCh).(*LocalParty)
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
deriveChildKey:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break deriveChildKey

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
			if atomic.LoadInt32(&ended) == int32(len(derivekeyPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received derive result from %d participants", ended)

				break deriveChildKey
			}
		}
	}
}

func TestE2EConcurrentFromEDDSA(t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

	// PHASE: load keygen fixtures
	keys, derivekeyPIDs, err := LoadKeygenTestFixtures(testThreshold+1, testFixtureDirFormatEDDSA) // 0 -- testParticipants-testThreshold-1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(derivekeyPIDs))

	// PHASE: deriveChildKey

	p2pCtx := tss.NewPeerContext(derivekeyPIDs)
	parties := make([]*LocalParty, 0, len(derivekeyPIDs))

	errCh := make(chan *tss.Error, len(derivekeyPIDs))
	outCh := make(chan tss.Message, len(derivekeyPIDs))
	// endCh := make(chan common.SignatureData, len(derivekeyPIDs))
	endCh := make(chan tss.Message, len(derivekeyPIDs))

	updater := test.SharedPartyUpdater

	path := []byte("/6667'/")
	chainCode := []byte("testChainCodeABC")
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(derivekeyPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, derivekeyPIDs[i], len(derivekeyPIDs), testThreshold, false, 0)

		P := NewLocalParty(path, chainCode, params, keys[i], outCh, endCh).(*LocalParty)
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
deriveChildKey:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break deriveChildKey

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
			if atomic.LoadInt32(&ended) == int32(len(derivekeyPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received derive result from %d participants", ended)

				break deriveChildKey
			}
		}
	}
}

func TestE2EConcurrentFromSCHNORR(t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

	// PHASE: load keygen fixtures
	keys, derivekeyPIDs, err := LoadKeygenTestFixtures(testThreshold+1, testFixtureDirFormatSCHNORR) // 0 -- testParticipants-testThreshold-1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(derivekeyPIDs))

	// PHASE: deriveChildKey

	p2pCtx := tss.NewPeerContext(derivekeyPIDs)
	parties := make([]*LocalParty, 0, len(derivekeyPIDs))

	errCh := make(chan *tss.Error, len(derivekeyPIDs))
	outCh := make(chan tss.Message, len(derivekeyPIDs))
	// endCh := make(chan common.SignatureData, len(derivekeyPIDs))
	endCh := make(chan tss.Message, len(derivekeyPIDs))

	updater := test.SharedPartyUpdater

	path := []byte("/6667'/")
	chainCode := []byte("testChainCodeABC")
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(derivekeyPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, derivekeyPIDs[i], len(derivekeyPIDs), testThreshold, false, 0)

		P := NewLocalParty(path, chainCode, params, keys[i], outCh, endCh).(*LocalParty)
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
deriveChildKey:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			log.Error(ctx, "Error: %s", err)
			assert.FailNow(t, err.Error())
			break deriveChildKey

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
			if atomic.LoadInt32(&ended) == int32(len(derivekeyPIDs)) {
				// already verified in finalize.go
				t.Logf("Done. Received derive result from %d participants", ended)

				break deriveChildKey
			}
		}
	}
}

func LoadKeygenTestFixtures(qty int, fixtureBase string, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	// for i := start; i < qty; i++ {
	for i := 0; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i+start, fixtureBase)
		bz, err := os.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			if fixtureBase == testFixtureDirFormatEDDSA {
				kbxj.SetCurve(tss.Edwards())
			} else {
				kbxj.SetCurve(tss.S256())
			}
		}
		// ToDo ecdsa different field name
		// key.PubKey.SetCurve(tss.S256())
		keys = append(keys, key)
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("Peer{%d}", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}
