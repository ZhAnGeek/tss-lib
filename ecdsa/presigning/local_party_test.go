// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning_test

import (
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	. "github.com/binance-chain/tss-lib/ecdsa/presigning"
	sign "github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: presigning
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *PreSignatureData, len(signPIDs))
	dumpCh := make(chan *LocalDump, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, endCh, dumpCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	preSigDatas := make([]*PreSignatureData, len(signPIDs))

	var presignended int32
presigning:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			fmt.Println("#################### ", du.Index, du.RoundNum)
			//i := du.Index
			//params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
			//keyDerivationDelta := big.NewInt(0)
			////newPi := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, endCh, dumpCh).(*LocalParty)
			//newPi, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, du, outCh, endCh, dumpCh)
			//if err != nil {
			//	common.Logger.Errorf("Error: %s", err)
			//	assert.FailNow(t, err.Error())
			//}
			//parties[i] = newPi.(*LocalParty)
			//go newPi.Start()
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

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

		case predata := <-endCh:
			atomic.AddInt32(&presignended, 1)
			preSigDatas[predata.UnmarshalIndex()] = predata
			t.Logf("%d ssid: %d", predata.UnmarshalIndex(), new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignended) == int32(len(signPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignended)

				goto signing
			}
		}
	}
signing:
	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx = tss.NewPeerContext(signPIDs)
	signParties := make([]*sign.LocalParty, 0, len(signPIDs))

	errCh = make(chan *tss.Error, len(signPIDs))
	outCh = make(chan tss.Message, len(signPIDs))
	sigCh := make(chan common.SignatureData, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh).(*sign.LocalParty)
		signParties = append(signParties, P)
		go func(P *sign.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var signended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&signended, 1)
			if atomic.LoadInt32(&signended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", signended)

				return
			}
		}
	}
}

func TestR2RConcurrent(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: presigning
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties_presign1 := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs)*10)
	outCh := make(chan tss.Message, len(signPIDs)*10)
	endCh := make(chan *PreSignatureData, len(signPIDs)*10)
	dumpCh := make(chan *LocalDump, len(signPIDs)*10)

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, endCh, dumpCh).(*LocalParty)
		parties_presign1 = append(parties_presign1, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	r1msgs := make([]tss.Message, 0)
	r1dumps := make([]*LocalDump, len(signPIDs))
	var presign_1ended int32

presign_1_loop:
	for {
		fmt.Printf("Presign1 select messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.Index
			r1dumps[i] = du
			atomic.AddInt32(&presign_1ended, 1)
			if atomic.LoadInt32(&presign_1ended) == int32(len(signPIDs)) {
				t.Logf("Presign 1 all done. Received dump data from %d participants", presign_1ended)

				goto presign_2
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_1_loop

		case msg := <-outCh:
			r1msgs = append(r1msgs, msg)
		}
	}
presign_2:
	//errCh = make(chan *tss.Error, len(signPIDs))
	//outCh = make(chan tss.Message, len(signPIDs))
	//endCh = make(chan *PreSignatureData, len(signPIDs))
	//dumpCh = make(chan *LocalDump, len(signPIDs))

	parties_presign1 = nil
	parties_presign2 := make([]*LocalParty, 0, len(signPIDs))
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r1dumps[i], outCh, endCh, dumpCh, 1)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign2 = append(parties_presign2, P.(*LocalParty))
	}

	r2msgs := make([]tss.Message, 0) //, len(signPIDs)*(len(signPIDs)-1))
	r2dumps := make([]*LocalDump, len(signPIDs))
	var presign_2ended int32

	// update by msg
	for i, msg := range r1msgs {
		fmt.Println("update by r1msgs", i, msg.GetFrom(), "=>", msg.GetTo())
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign2 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
			}
			go updater(parties_presign2[dest[0].Index], msg, errCh)
		}

	}
presign_2_loop:
	for {
		fmt.Printf("Presign2 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.Index
			r2dumps[i] = du
			atomic.AddInt32(&presign_2ended, 1)
			if atomic.LoadInt32(&presign_2ended) == int32(len(signPIDs)) {
				t.Logf("Presign 2 all done. Received dump data from %d participants", presign_2ended)

				goto presign_3
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_2_loop

		case msg := <-outCh:
			//fmt.Println("presign2 received message", msg.GetFrom(), msg.GetTo())
			r2msgs = append(r2msgs, msg)
		}
	}
presign_3:
	//errCh = make(chan *tss.Error, len(signPIDs))
	//outCh = make(chan tss.Message, len(signPIDs))
	//endCh = make(chan *PreSignatureData, len(signPIDs))
	//dumpCh = make(chan *LocalDump, len(signPIDs))

	parties_presign2 = nil
	parties_presign3 := make([]*LocalParty, 0, len(signPIDs))
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r2dumps[i], outCh, endCh, dumpCh, 2)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign3 = append(parties_presign3, P.(*LocalParty))
	}

	r3msgs := make([]tss.Message, 0) //, len(signPIDs)*(len(signPIDs)-1))
	r3dumps := make([]*LocalDump, len(signPIDs))
	var presign_3ended int32

	// update by msg
	for i, msg := range r2msgs {
		fmt.Println("update by r2msgs", i, msg.GetFrom(), "=>", msg.GetTo())
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign3 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
			}
			go updater(parties_presign3[dest[0].Index], msg, errCh)
		}

	}
presign_3_loop:
	for {
		fmt.Printf("Presign3 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.Index
			r3dumps[i] = du
			atomic.AddInt32(&presign_3ended, 1)
			if atomic.LoadInt32(&presign_3ended) == int32(len(signPIDs)) {
				t.Logf("Presign 3 all done. Received dump data from %d participants", presign_3ended)

				goto presign_out
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_3_loop

		case msg := <-outCh:
			//fmt.Println("presign3 received message", msg.GetFrom(), msg.GetTo())
			r3msgs = append(r3msgs, msg)
		}
	}
presign_out:
// setup parties_sign
// update r3msgs
}

func TestE2EConcurrentWithHD(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)

	il, extendedChildPk, errorDerivation := DerivingPubkeyFromPath(keys[0].ECDSAPub, chainCode, []uint32{12, 209, 3}, tss.S256())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")
	keyDerivationDelta := il

	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keys, &extendedChildPk.PublicKey, tss.S256())
	assert.NoErrorf(t, err, "there should not be an error setting the derived keys")

	// PHASE: presigning
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *PreSignatureData, len(signPIDs))
	dumpCh := make(chan *LocalDump, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, endCh, dumpCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	preSigDatas := make([]*PreSignatureData, len(signPIDs))

	var presignended int32
presigning:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

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

		case predata := <-endCh:
			atomic.AddInt32(&presignended, 1)
			preSigDatas[predata.UnmarshalIndex()] = predata
			t.Logf("%d ssid: %d", predata.UnmarshalIndex(), new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignended) == int32(len(signPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignended)

				goto signing
			}
		}
	}
signing:
	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx = tss.NewPeerContext(signPIDs)
	signParties := make([]*sign.LocalParty, 0, len(signPIDs))

	errCh = make(chan *tss.Error, len(signPIDs))
	outCh = make(chan tss.Message, len(signPIDs))
	sigCh := make(chan common.SignatureData, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh).(*sign.LocalParty)
		signParties = append(signParties, P)
		go func(P *sign.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var signended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&signended, 1)
			if atomic.LoadInt32(&signended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", signended)

				return
			}
		}
	}
}