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

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/crypto/hash2curve"
	curves "github.com/Safulet/tss-lib-private/crypto/pallas"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants             = test.TestParticipants
	testThreshold                = test.TestThreshold
	testFixtureDirFormatECDSA    = "%s/../test/_ecdsa_fixtures_%d_%d"
	testFixtureDirFormatEDDSA    = "%s/../test/_eddsa_fixtures_%d_%d"
	testFixtureDirFormatSCHNORR  = "%s/../test/_schnorr_fixtures_%d_%d"
	testFixtureDirFormatPALLAS   = "%s/../test/_pallas_fixtures_%d_%d"
	testFixtureDirFormatBLSG2    = "%s/../test/_bls_fixtures_g2_%d_%d"
	testFixtureDirFormatBLSG1    = "%s/../test/_bls_fixtures_g1_%d_%d"
	testFixtureDirFormatKCDSA    = "%s/../test/_kcdsa_fixtures_%d_%d"
	testFixtureFileFormat        = "keygen_data_%d.json"
	testFixtureDirFormatStarkNet = "%s/../test/_ecdsa_fixtures_%d_%d/starkcurve"
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

func TestStarkCurve(t *testing.T) {
	ec := tss.StarkCurve()
	msg := []byte{1, 2, 3}
	dst := []byte("separator")
	g1p, _ := starkcurve.HashToG1(msg, dst)
	_, err := crypto.NewECPoint(ec, g1p.X.BigInt(new(big.Int)), g1p.Y.BigInt(new(big.Int)))
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
	endCh := make(chan *DeriveKeyResultMessage, len(derivekeyPIDs))

	updater := test.SharedPartyUpdater

	n, _ := new(big.Int).SetString("2147483648", 10)
	index := n.Bytes()
	chainCode := []byte("testChainCodeABC")
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(derivekeyPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, derivekeyPIDs[i], len(derivekeyPIDs), testThreshold, false, 0)

		P := NewLocalParty(index, chainCode, params, keys[i], outCh, endCh).(*LocalParty)
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
	deltas := [][]byte{}
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
		case res := <-endCh:
			atomic.AddInt32(&ended, 1)
			delta := res.GetDelta()
			t.Log("delta:", new(big.Int).SetBytes(delta).String())
			deltas = append(deltas, delta)
			if atomic.LoadInt32(&ended) == int32(len(derivekeyPIDs)) {
				t.Logf("Done. Received derive result from %d participants", ended)

				break deriveChildKey
			}
		}
	}
	assert.Equal(t, len(derivekeyPIDs), len(deltas))
	assert.Equal(t, deltas[0], deltas[1])
}

func TestE2EConcurrent(t *testing.T) {
	E2EConcurrent(tss.S256(), testFixtureDirFormatECDSA, t)
	E2EConcurrent(tss.Edwards(), testFixtureDirFormatEDDSA, t)
	E2EConcurrent(tss.S256(), testFixtureDirFormatSCHNORR, t)
	E2EConcurrent(tss.Bls12381G2(), testFixtureDirFormatBLSG2, t)
	E2EConcurrent(tss.Bls12381G1(), testFixtureDirFormatBLSG1, t)
	E2EConcurrent(tss.Pallas(), testFixtureDirFormatPALLAS, t)
	E2EConcurrent(tss.Curve25519(), testFixtureDirFormatKCDSA, t)
	E2EConcurrent(tss.StarkCurve(), testFixtureDirFormatStarkNet, t)
}

func TestLocalCalc(t *testing.T) {
	ec := tss.S256()
	fixtureDir := testFixtureDirFormatECDSA
	keys, _, err := LoadKeygenTestFixtures(testThreshold+1, ec, fixtureDir) // 0 -- testParticipants-testThreshold-1)
	assert.NoError(t, err)

	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: testThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)

	E2EConcurrent(tss.S256(), testFixtureDirFormatECDSA, t)
	refDelta, ok := new(big.Int).SetString("26584850041541184611210048611703299842106441087558008034516645976981837299974", 10)
	assert.True(t, ok)
	refSk := new(big.Int).Mod(new(big.Int).Add(sk, refDelta), ec.Params().N)
	n, _ := new(big.Int).SetString("2147483648", 10)
	index := n.Bytes()
	chainCode := []byte("testChainCodeABC")
	cSk, _, err := CalcChildVaultPrivateKey(ec, sk, index, chainCode)
	assert.NoError(t, err)
	fmt.Println("refSk:", refSk.String())
	fmt.Println("  cSk:", cSk.String())
	assert.Zero(t, cSk.Cmp(refSk))
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
