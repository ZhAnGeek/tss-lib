// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/ckd"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/kcdsa/keygen"
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

	// only for test
	tss.SetCurve(tss.Curve25519())
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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}

	b.StartTimer()
	keyDerivation := new(big.Int).SetInt64(10)
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Curve25519(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		P := NewLocalParty(msg, params, keys[i], keyDerivation, outCh, endCh).(*LocalParty)
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
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200).Bytes()
	// init the parties
	wg := sync.WaitGroup{}

	// Derive chlid key vault
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)
	il, childKey, errorDerivation := DerivingPubkeyFromPath(ctx, keys[0].PubKey, chainCode, []uint32{12, 209, 3}, tss.EC())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")
	keyDerivationDelta := il
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Curve25519(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

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

		case sig := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				rb := common.ReverseBytes(sig.R)
				sb := common.ReverseBytes(sig.S)
				s := new(big.Int).SetBytes(rb)
				e := new(big.Int).SetBytes(sb)
				assert.True(t, VerifySig(tss.Curve25519(), ctx, s, e, msg, &childKey.PublicKey))
				t.Logf("Done. Received save data from %d participants", ended)

				break signing
			}
		}
	}
}

func DerivingPubkeyFromPath(ctx context.Context, masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk, err := crypto.NewECPoint(ec, masterPub.X(), masterPub.Y())
	if err != nil {
		return nil, nil, err
	}

	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  *pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
	}

	return ckd.DeriveChildKeyFromHierarchyForKCDSA(ctx, path, extendedParentPk, ec.Params().N, ec)
}
