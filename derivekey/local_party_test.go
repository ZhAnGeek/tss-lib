// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/crypto/hash2curve"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants            = test.TestParticipants
	testThreshold               = test.TestThreshold
	testFixtureDirFormatECDSA   = "%s/../test/_ecdsa_fixtures_%d_%d"
	testFixtureDirFormatEDDSA   = "%s/../test/_eddsa_fixtures_%d_%d"
	testFixtureDirFormatSCHNORR = "%s/../test/_schnorr_fixtures_%d_%d"
	testFixtureDirFormatPALLAS  = "%s/../test/_pallas_fixtures_%d_%d"
	testFixtureDirFormatBLS     = "%s/../test/_bls_fixtures_%d_%d"
	testFixtureDirFormatKCDSA   = "%s/../test/_kcdsa_fixtures_%d_%d"
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
	hashToCurve, err := hash2curve.Secp256k1_XMDSHA256_SSWU_RO_.Get([]byte(dst))
	assert.NoError(t, err, "should init h2c")
	h2cPoint := hashToCurve.Hash([]byte("abc"))
	h2cPx := h2cPoint.X().Polynomial()[0]
	h2cPy := h2cPoint.Y().Polynomial()[0]
	fmt.Println("x:", fmt.Sprintf("0x%x", h2cPx))
	fmt.Println("y:", fmt.Sprintf("0x%x", h2cPy))
	_, err = crypto.NewECPoint(tss.S256(), h2cPx, h2cPy)
	assert.NoError(t, err, "should hash to curve")
}

func TestH2CBLS(t *testing.T) {
	dst := "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
	hashToCurve, err := hash2curve.BLS12381G2_XMDSHA256_SSWU_RO_.Get([]byte(dst))
	assert.NoError(t, err, "should init h2c")
	h2cPoint := hashToCurve.Hash([]byte("abc"))
	h2cPx1 := h2cPoint.X().Polynomial()[0]
	h2cPx2 := h2cPoint.X().Polynomial()[1]
	h2cPy1 := h2cPoint.Y().Polynomial()[0]
	h2cPy2 := h2cPoint.Y().Polynomial()[1]
	fmt.Println("x1:", fmt.Sprintf("0x%x", h2cPx1))
	fmt.Println("x2:", fmt.Sprintf("0x%x", h2cPx2))
	fmt.Println("y1:", fmt.Sprintf("0x%x", h2cPy1))
	fmt.Println("y2:", fmt.Sprintf("0x%x", h2cPy2))
	xBzs := make([]byte, 96)
	yBzs := make([]byte, 96)
	copy(xBzs[:48], common.PadToLengthBytesInPlace(h2cPx2.Bytes(), 48))
	copy(xBzs[48:], common.PadToLengthBytesInPlace(h2cPx1.Bytes(), 48))
	copy(yBzs[:48], common.PadToLengthBytesInPlace(h2cPy2.Bytes(), 48))
	copy(yBzs[48:], common.PadToLengthBytesInPlace(h2cPy1.Bytes(), 48))
	_, err = bls12381.FromIntToPointG2(new(big.Int).SetBytes(xBzs),
		new(big.Int).SetBytes(yBzs))
	_, err = crypto.NewECPoint(tss.Bls12381G2(), new(big.Int).SetBytes(xBzs),
		new(big.Int).SetBytes(yBzs))
	assert.NoError(t, err, "should hash to curve")
}

func TestH2CPallas(t *testing.T) {
	ec := curves.PALLAS()
	msg := []byte("abc")
	P := ec.Point.Hash(msg).(*curves.PointPallas)

	fmt.Println("x:", P.X().BigInt().String())
	fmt.Println("y:", P.Y().BigInt().String())

	_, err := crypto.NewECPoint(tss.Pallas(), P.X().BigInt(), P.Y().BigInt())
	assert.NoError(t, err, "should hash to curve")
}

func E2EConcurrent(ec elliptic.Curve, fixtureDir string, t *testing.T) {
	ctx := context.Background()
	setUp(log.ErrorLevel)

	// PHASE: load keygen fixtures
	keys, derivekeyPIDs, err := LoadKeygenTestFixtures(testThreshold+1, ec, fixtureDir) // 0 -- testParticipants-testThreshold-1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(derivekeyPIDs))

	// PHASE: deriveChildKey
	p2pCtx := tss.NewPeerContext(derivekeyPIDs)
	parties := make([]*LocalParty, 0, len(derivekeyPIDs))

	errCh := make(chan *tss.Error, len(derivekeyPIDs))
	outCh := make(chan tss.Message, len(derivekeyPIDs))
	endCh := make(chan tss.Message, len(derivekeyPIDs))

	updater := test.SharedPartyUpdater

	path := []byte("/6667'/")
	chainCode := []byte("testChainCodeABC")
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(derivekeyPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, derivekeyPIDs[i], len(derivekeyPIDs), testThreshold, false, 0)

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

		case msg := <-endCh:
			atomic.AddInt32(&ended, 1)
			bz, _, err := msg.WireBytes()
			assert.NoError(t, err)
			pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
			assert.NoError(t, err)
			res := pMsg.Content().(*DeriveKeyResultMessage)
			ilNum := res.GetDelta()
			t.Log(msg.GetFrom(), "ilNum:", new(big.Int).SetBytes(ilNum).String())
			if atomic.LoadInt32(&ended) == int32(len(derivekeyPIDs)) {
				t.Logf("Done. Received derive result from %d participants", ended)

				break deriveChildKey
			}
		}
	}
}

func TestE2EConcurrent(t *testing.T) {
	E2EConcurrent(tss.S256(), testFixtureDirFormatECDSA, t)
	E2EConcurrent(tss.Edwards(), testFixtureDirFormatEDDSA, t)
	E2EConcurrent(tss.S256(), testFixtureDirFormatSCHNORR, t)
	E2EConcurrent(tss.Bls12381G2(), testFixtureDirFormatBLS, t)
	E2EConcurrent(tss.Pallas(), testFixtureDirFormatPALLAS, t)
	E2EConcurrent(tss.Curve25519(), testFixtureDirFormatKCDSA, t)
}

func LoadKeygenTestFixtures(qty int, ec elliptic.Curve, fixtureBase string, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := 0; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i+start, fixtureBase)
		bz, err := ioutil.ReadFile(fixtureFilePath)
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
			kbxj.SetCurve(ec)
		}
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