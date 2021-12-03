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
	dumpCh := make(chan *LocalDumpPB, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

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
			fmt.Println(du.Index, du.RoundNum)
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
	sdumpCh := make(chan *sign.LocalDump, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
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
	setUp("error")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// Use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties_presign_1 := make([]*LocalParty, 0, len(signPIDs))

	// Channels
	errCh := make(chan *tss.Error, len(signPIDs)*10)
	outCh := make(chan tss.Message, len(signPIDs)*10)
	preSigCh := make(chan *PreSignatureData, len(signPIDs)*10)
	dumpCh := make(chan *LocalDumpPB, len(signPIDs)*10)
	sdumpCh := make(chan *sign.LocalDump, len(signPIDs)*10)

	sigCh := make(chan common.SignatureData, len(signPIDs))

	// Updater
	updater := test.SharedPartyUpdater

	// Presign 1
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, preSigCh, dumpCh).(*LocalParty)
		parties_presign_1 = append(parties_presign_1, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(parties_presign_1[i])
		fmt.Printf("Party%2d [presign 1]: initialized and running...\n", i)
	}

	r1msgs := make([]tss.Message, 0)
	r1dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_1_ended int32

presign_1_loop:
	for {
		//fmt.Printf("Presign1 select messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r1dumps[i] = du
			atomic.AddInt32(&presign_1_ended, 1)
			fmt.Printf("Party%2d [presign 1]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_1_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 1 all done. Received dump data from %d participants", presign_1_ended)

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
	parties_presign_1 = nil
	parties_presign_2 := make([]*LocalParty, 0, len(signPIDs))
	// Presign 2
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign 2]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r1dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_2 = append(parties_presign_2, P.(*LocalParty))
	}

	r2msgs := make([]tss.Message, 0)
	r2dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_2_ended int32

	// Consuming r1msgs
	fmt.Printf("Parties consuming r1msgs and run... \n")
	for i, msg := range r1msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_2 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_2[dest[0].Index], msg, errCh)
		}

	}

presign_2_loop:
	for {
		//fmt.Printf("Presign2 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r2dumps[i] = du
			atomic.AddInt32(&presign_2_ended, 1)
			fmt.Printf("Party%2d [presign 2]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_2_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 2 all done. Received dump data from %d participants", presign_2_ended)

				goto presign_3
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_2_loop

		case msg := <-outCh:
			r2msgs = append(r2msgs, msg)
		}
	}

presign_3:
	parties_presign_2 = nil
	parties_presign_3 := make([]*LocalParty, 0, len(signPIDs))

	// Presign 3
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign 3]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r2dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_3 = append(parties_presign_3, P.(*LocalParty))
	}

	r3msgs := make([]tss.Message, 0) //, len(signPIDs)*(len(signPIDs)-1))
	r3dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_3_ended int32

	// Consuming r2msgs
	fmt.Printf("Parties consuming r2msgs and run... \n")
	for i, msg := range r2msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_3 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_3[dest[0].Index], msg, errCh)
		}

	}

presign_3_loop:
	for {
		//fmt.Printf("Presign3 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r3dumps[i] = du
			atomic.AddInt32(&presign_3_ended, 1)
			fmt.Printf("Party%2d [presign 3]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_3_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 3 all done. Received dump data from %d participants", presign_3_ended)

				goto presign_out
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_3_loop

		case msg := <-outCh:
			r3msgs = append(r3msgs, msg)
		}
	}

presign_out:
	// setup parties_sign
	// update r3msgs
	parties_presign_3 = nil
	parties_presign_out := make([]*LocalParty, 0, len(signPIDs))

	// Presign out
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign out]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r3dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_out = append(parties_presign_out, P.(*LocalParty))
	}

	preSigs := make([]*PreSignatureData, len(signPIDs))
	var presign_out_ended int32

	// Consuming r3msgs
	fmt.Printf("Parties consuming r3msgs and run... \n")
	for i, msg := range r3msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_out {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_out[dest[0].Index], msg, errCh)
		}

	}

presign_out_loop:
	for {
		//fmt.Printf("Presignout generating presig...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_out_loop

		case predata := <-preSigCh:
			atomic.AddInt32(&presign_out_ended, 1)
			preSigs[predata.UnmarshalIndex()] = predata
			i := predata.UnmarshalIndex()
			ssid := new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64()
			fmt.Printf("Party%2d [presign out]: done and stored preSig(%d) \n", i, ssid)
			if atomic.LoadInt32(&presign_out_ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presign_out_ended)

				goto signing
			}
		}
	}
	parties_presign_out = nil

signing:
	// Signing
	parties_signing := make([]*sign.LocalParty, 0, len(signPIDs))
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigs[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
		parties_signing = append(parties_signing, P)
		go func(P *sign.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
		fmt.Printf("Party%2d [sign 1]: initialized and running...\n", i)
	}

	var sign_ended int32
	for {
		//fmt.Printf("Signing selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties_signing {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties_signing[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&sign_ended, 1)
			if atomic.LoadInt32(&sign_ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", sign_ended)

				return
			}
		}
	}
}

func TestR2RWithIdentification(t *testing.T) {
	setUp("error")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// Use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties_presign_1 := make([]*LocalParty, 0, len(signPIDs))

	// Channels
	errCh := make(chan *tss.Error, len(signPIDs)*10)
	outCh := make(chan tss.Message, len(signPIDs)*10)
	preSigCh := make(chan *PreSignatureData, len(signPIDs)*10)
	dumpCh := make(chan *LocalDumpPB, len(signPIDs)*10)

	// Updater
	updater := test.SharedPartyUpdater

	// Presign 1
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(params, keys[i], keyDerivationDelta, outCh, preSigCh, dumpCh).(*LocalParty)
		parties_presign_1 = append(parties_presign_1, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(parties_presign_1[i])
		fmt.Printf("Party%2d [presign 1]: initialized and running...\n", i)
	}

	r1msgs := make([]tss.Message, 0)
	r1dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_1_ended int32

presign_1_loop:
	for {
		//fmt.Printf("Presign1 select messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r1dumps[i] = du
			atomic.AddInt32(&presign_1_ended, 1)
			fmt.Printf("Party%2d [presign 1]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_1_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 1 all done. Received dump data from %d participants", presign_1_ended)

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
	parties_presign_1 = nil
	parties_presign_2 := make([]*LocalParty, 0, len(signPIDs))
	// Presign 2
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign 2]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r1dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_2 = append(parties_presign_2, P.(*LocalParty))
	}

	r2msgs := make([]tss.Message, 0)
	r2dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_2_ended int32

	// Consuming r1msgs
	fmt.Printf("Parties consuming r1msgs and run... \n")
	for i, msg := range r1msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_2 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_2[dest[0].Index], msg, errCh)
		}

	}

presign_2_loop:
	for {
		//fmt.Printf("Presign2 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r2dumps[i] = du
			atomic.AddInt32(&presign_2_ended, 1)
			fmt.Printf("Party%2d [presign 2]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_2_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 2 all done. Received dump data from %d participants", presign_2_ended)

				goto presign_3
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_2_loop

		case msg := <-outCh:
			r2msgs = append(r2msgs, msg)
		}
	}

presign_3:
	parties_presign_2 = nil
	parties_presign_3 := make([]*LocalParty, 0, len(signPIDs))

	// Presign 3
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign 3]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r2dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_3 = append(parties_presign_3, P.(*LocalParty))
	}

	r3msgs := make([]tss.Message, 0) //, len(signPIDs)*(len(signPIDs)-1))
	r3dumps := make([]*LocalDumpPB, len(signPIDs))
	var presign_3_ended int32

	// Consuming r2msgs
	fmt.Printf("Parties consuming r2msgs and run... \n")
	for i, msg := range r2msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_3 {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_3[dest[0].Index], msg, errCh)
		}

	}

presign_3_loop:
	for {
		//fmt.Printf("Presign3 selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			//i := du.Index
			r3dumps[i] = du
			atomic.AddInt32(&presign_3_ended, 1)
			fmt.Printf("Party%2d [presign 3]: done and status dumped \n", i)
			if atomic.LoadInt32(&presign_3_ended) == int32(len(signPIDs)) {
				t.Logf("Presign 3 all done. Received dump data from %d participants", presign_3_ended)

				goto presign_out
			}
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_3_loop

		case msg := <-outCh:
			r3msgs = append(r3msgs, msg)
		}
	}

presign_out:
	// setup parties_sign
	// update r3msgs
	parties_presign_3 = nil
	parties_presign_out := make([]*LocalParty, 0, len(signPIDs))

	// Presign out
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign out]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r3dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_out = append(parties_presign_out, P.(*LocalParty))
	}

	r4dumps := make([]*LocalDumpPB, len(signPIDs))
	preSigs := make([]*PreSignatureData, len(signPIDs))
	var presign_out_ended int32

	// Consuming r3msgs
	fmt.Printf("Parties consuming r3msgs and run... \n")
	for i, msg := range r3msgs {
		dest := msg.GetTo()
		if dest == nil {
			for _, P := range parties_presign_out {
				if P.PartyID().Index == msg.GetFrom().Index {
					continue
				}
				go updater(P, msg, errCh)
			}
		} else {
			if dest[0].Index == msg.GetFrom().Index {
				t.Fatalf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(parties_presign_out[dest[0].Index], msg, errCh)
		}

	}

presign_out_loop:
	for {
		//fmt.Printf("Presignout generating presig...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			r4dumps[i] = du
			atomic.AddInt32(&presign_out_ended, 1)
			if atomic.LoadInt32(&presign_out_ended) == int32(len(signPIDs)) {
				t.Logf("Presign_out Done. Received dump data from %d participants", presign_out_ended)

				goto identification
			}

		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presign_out_loop

		case predata := <-preSigCh:
			preSigs[predata.UnmarshalIndex()] = predata
			i := predata.UnmarshalIndex()
			ssid := new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64()
			fmt.Printf("Party%2d [presign out]: done and stored preSig(%d) \n", i, ssid)
		}
	}
	parties_presign_out = nil

identification:
	parties_presign_out = nil
	parties_presign_identification := make([]*LocalParty, 0, len(signPIDs))

	// Presign out
	for i := 0; i < len(signPIDs); i++ {
		fmt.Printf("Party%2d [presign identification]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true)

		keyDerivationDelta := big.NewInt(0)
		P, err := RestoreLocalParty(params, keys[i], keyDerivationDelta, r4dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		parties_presign_identification = append(parties_presign_identification, P.(*LocalParty))
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(parties_presign_identification[i])
		fmt.Printf("Party%2d [presign identification]: running...\n", i)
	}

	var identification_ended int32
	for {
		//fmt.Printf("Signing selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties_presign_identification {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties_presign_identification[dest[0].Index], msg, errCh)
			}

		case <-dumpCh:
			atomic.AddInt32(&identification_ended, 1)
			if atomic.LoadInt32(&identification_ended) == int32(len(signPIDs)) {
				t.Logf("Identification Done. Received from %d participants", identification_ended)

				return
			}
		}
	}
}
func TestE2EConcurrentHD(t *testing.T) {
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
	dumpCh := make(chan *LocalDumpPB, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

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
			fmt.Println(du.Index, du.RoundNum)
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
	sdumpCh := make(chan *sign.LocalDump, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false)

		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
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
