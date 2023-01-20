// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log/v2"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	. "github.com/Safulet/tss-lib-private/ecdsa/presigning"
	sign "github.com/Safulet/tss-lib-private/ecdsa/signing"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
	"google.golang.org/protobuf/proto"
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

func updatePartiesByMessages(ctx context.Context, parties []*LocalParty,
	msgs []tss.Message,
	updater func(ctx context.Context, party tss.Party, msg tss.Message, errCh chan<- *tss.Error),
	errCh chan *tss.Error) error {
	for i, msg := range msgs {
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
				return fmt.Errorf("party %d tried to send a message(%d) to itself (%d)", dest[0].Index, i, msg.GetFrom().Index)
			}
			go updater(ctx, parties[dest[0].Index], msg, errCh)
		}
	}
	return nil
}

func fetchingMessages(
	ctx context.Context,
	dumpCh chan *LocalDumpPB,
	dumps []*LocalDumpPB,
	N int,
	errCh chan *tss.Error,
	outCh chan tss.Message,
	msgs *[]tss.Message,
	preSigCh chan *PreSignatureData,
	preSigs []*PreSignatureData,
	sigCh chan common.SignatureData,
	signOutCh chan tss.Message,
	signParties []*sign.LocalParty,
	updater func(ctx context.Context, party tss.Party, msg tss.Message, errCh chan<- *tss.Error),
	numMsgPerRound int,
) error {
	var ended1, ended2 int32
	for {
		// fmt.Printf("Presign1 select messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			// Simulate serilize and restore
			dum, _ := proto.Marshal(du)
			dumStr := base64.StdEncoding.EncodeToString(dum)
			dumStrDec, _ := base64.StdEncoding.DecodeString(dumStr)
			var duRestored LocalDumpPB
			err := proto.Unmarshal(dumStrDec, &duRestored)
			if err != nil {
				return err
			}

			i := duRestored.UnmarshalIndex()
			dumps[i] = &duRestored
			atomic.AddInt32(&ended1, 1)
			if atomic.LoadInt32(&ended1) == int32(N) && atomic.LoadInt32(&ended2) == int32(numMsgPerRound*N*(N-1)) {
				return nil
			}

		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			return err

		case msg := <-outCh:
			*msgs = append(*msgs, msg)
			atomic.AddInt32(&ended2, 1)
			if atomic.LoadInt32(&ended1) == int32(N) && atomic.LoadInt32(&ended2) == int32(numMsgPerRound*N*(N-1)) {
				return nil
			}

		case predata := <-preSigCh:
			atomic.AddInt32(&ended1, 1)
			preSigs[predata.UnmarshalIndex()] = predata
			i := predata.UnmarshalIndex()
			ssid := new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64()
			fmt.Printf("Party%2d [presign out]: done and stored preSig(%d) \n", i, ssid)
			if atomic.LoadInt32(&ended1) == int32(N) {
				return nil
			}

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					return fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&ended1, 1)
			if atomic.LoadInt32(&ended1) == int32(N) {
				fmt.Printf("Signing Done. Received signature data from %d participants\n", N)

				return nil
			}
		}
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
	setUp("error")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, _ := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)

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
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		P := NewLocalParty(params, keys[i], outCh, endCh, dumpCh).(*LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	b.StartTimer()
	preSigDatas := make([]*PreSignatureData, len(signPIDs))

	var presignEnded int32
presigning:
	for {
		// fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case <-dumpCh:
		case <-errCh:
			break presigning
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
		case predata := <-endCh:
			atomic.AddInt32(&presignEnded, 1)
			preSigDatas[predata.UnmarshalIndex()] = predata
			if atomic.LoadInt32(&presignEnded) == int32(len(signPIDs)) {
				goto signing
			}
		}
	}
signing:
	// b.ResetTimer()
	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	b.StopTimer()
	p2pCtx = tss.NewPeerContext(signPIDs)
	signParties := make([]*sign.LocalParty, 0, len(signPIDs))

	errCh = make(chan *tss.Error, len(signPIDs))
	outCh = make(chan tss.Message, len(signPIDs))
	sigCh := make(chan common.SignatureData, len(signPIDs))
	sdumpCh := make(chan *sign.LocalDumpPB, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
		signParties = append(signParties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range signParties {
		wg.Add(1)
		go func(P *sign.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	b.StartTimer()

	var signEnded int32
	for {
		select {
		case <-errCh:
			return
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}
		case <-sigCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				return
			}
		}
	}
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
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
	outCh := make(chan tss.Message, len(signPIDs)*2)
	endCh := make(chan *PreSignatureData, len(signPIDs))
	dumpCh := make(chan *LocalDumpPB, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		P := NewLocalParty(params, keys[i], outCh, endCh, dumpCh).(*LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	preSigDatas := make([]*PreSignatureData, len(signPIDs))

	var presignEnded int32
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
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case predata := <-endCh:
			atomic.AddInt32(&presignEnded, 1)
			preSigDatas[predata.UnmarshalIndex()] = predata
			t.Logf("%d ssid: %d", predata.UnmarshalIndex(), new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignEnded)

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
	sdumpCh := make(chan *sign.LocalDumpPB, len(signPIDs))

	updater = test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
		signParties = append(signParties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range signParties {
		wg.Add(1)
		go func(P *sign.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	var signEnded int32
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
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", signEnded)

				return
			}
		}
	}
}

func TestR2RConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp("info")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	N := len(signPIDs)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, N)

	// Use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	preSign1Parties := make([]*LocalParty, N)
	preSign2Parties := make([]*LocalParty, N)
	preSign3Parties := make([]*LocalParty, N)
	preSignOutParties := make([]*LocalParty, N)
	signParties := make([]*sign.LocalParty, N)

	// PreSign Channels
	errCh := make(chan *tss.Error, N*10)
	outCh := make(chan tss.Message, N*20)
	preSigCh := make(chan *PreSignatureData, N*10)
	preDumpCh := make(chan *LocalDumpPB, N*10)

	// Sign Channels
	sigCh := make(chan common.SignatureData, N)
	signDumpCh := make(chan *sign.LocalDumpPB, N*10)

	// Updater
	updater := test.SharedPartyUpdater

	// msgs and dumps
	r1msgs := make([]tss.Message, 0)
	r1dumps := make([]*LocalDumpPB, N)
	r2msgs := make([]tss.Message, 0)
	r2dumps := make([]*LocalDumpPB, N)
	r3msgs := make([]tss.Message, 0)
	r3dumps := make([]*LocalDumpPB, N)
	// pre signatures
	preSigs := make([]*PreSignatureData, N)

	// @Presign 1
	for i := 0; i < N; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], N, threshold, false, 0)

		P := NewLocalParty(params, keys[i], outCh, preSigCh, preDumpCh).(*LocalParty)
		preSign1Parties[i] = P
	}

	var wg sync.WaitGroup
	for i, party := range preSign1Parties {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
		fmt.Printf("Party%2d [presign 1]: initialized and running...\n", i)
	}
	wg.Wait()

	// Fetching messages produced by Presign 1
	if err := fetchingMessages(ctx, preDumpCh, r1dumps, N, errCh, outCh, &r1msgs, nil, nil, nil, nil, nil, nil, 2); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 1 all done. Received dump data from %d participants\n", N)

	// @Presign 2
	preSign1Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign 2]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], N, threshold, false, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r1dumps[i], outCh, preSigCh, preDumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSign2Parties[i] = P.(*LocalParty)
	}

	// Update parties@Presign2 by r1msgs
	fmt.Printf("Parties consuming r1msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSign2Parties, r1msgs, updater, errCh); err != nil {
		t.Error(err)
	}

	// Fetching messages produced by Presign 2
	if err := fetchingMessages(ctx, preDumpCh, r2dumps, N, errCh, outCh, &r2msgs, nil, nil, nil, nil, nil, nil, 1); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 2 all done. Received dump data from %d participants\n", N)

	// @Presign 3
	preSign2Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign 3]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], N, threshold, false, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r2dumps[i], outCh, preSigCh, preDumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSign3Parties[i] = P.(*LocalParty)
	}

	// Update parties@Presign3 by r2msgs
	fmt.Printf("Parties consuming r2msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSign3Parties, r2msgs, updater, errCh); err != nil {
		t.Error(err)
	}

	// Fetching messages produced by Presign 3
	if err := fetchingMessages(ctx, preDumpCh, r3dumps, N, errCh, outCh, &r3msgs, nil, nil, nil, nil, nil, nil, 1); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 3 all done. Received dump data from %d participants\n", N)

	// @Presign out
	preSign3Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign out]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], N, threshold, false, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r3dumps[i], outCh, preSigCh, preDumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSignOutParties[i] = P.(*LocalParty)
	}

	// Update parties@PresignOut by r3msgs
	fmt.Printf("Parties consuming r3msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSignOutParties, r3msgs, updater, errCh); err != nil {
		t.Error(err)
	}
	// Fetching messages produced by PresignOut
	if err := fetchingMessages(ctx, nil, nil, N, errCh, nil, nil, preSigCh, preSigs, nil, nil, nil, nil, 1); err != nil {
		t.Error(err)
	}
	fmt.Printf("PresignOut all done. Received preSig data from %d participants\n", N)

	// @Signing
	preSignOutParties = nil
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], N, threshold, false, 0)

		keyDerivationDelta := big.NewInt(0)
		P := sign.NewLocalParty(preSigs[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, signDumpCh).(*sign.LocalParty)
		signParties[i] = P
	}
	wg = sync.WaitGroup{}
	for i, party := range signParties {
		wg.Add(1)
		go func(P *sign.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
		fmt.Printf("Party%2d [sign 1]: initialized and running...\n", i)
	}
	wg.Wait()

	// Processing messages produced by signing
	if err := fetchingMessages(ctx, nil, nil, N, errCh, nil, nil, nil, nil, sigCh, outCh, signParties, updater, 1); err != nil {
		t.Error(err)
	}
}

func TestR2RWithIdentification(t *testing.T) {
	ctx := context.Background()
	setUp("error")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	N := len(signPIDs)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, N)

	// Use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	preSign1Parties := make([]*LocalParty, N)
	preSign2Parties := make([]*LocalParty, N)
	preSign3Parties := make([]*LocalParty, N)
	preSignOutParties := make([]*LocalParty, N)
	presignIdentificationParties := make([]*LocalParty, N)

	// Channels
	errCh := make(chan *tss.Error, N*10)
	outCh := make(chan tss.Message, N*10)
	preSigCh := make(chan *PreSignatureData, N*10)
	dumpCh := make(chan *LocalDumpPB, N*10)

	// Updater
	updater := test.SharedPartyUpdater

	// msgs and dumps
	r1msgs := make([]tss.Message, 0)
	r1dumps := make([]*LocalDumpPB, N)
	r2msgs := make([]tss.Message, 0)
	r2dumps := make([]*LocalDumpPB, N)
	r3msgs := make([]tss.Message, 0)
	r3dumps := make([]*LocalDumpPB, N)
	r4dumps := make([]*LocalDumpPB, N)
	preSigs := make([]*PreSignatureData, N)

	// @Presign 1
	for i := 0; i < N; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true, 0)

		P := NewLocalParty(params, keys[i], outCh, preSigCh, dumpCh).(*LocalParty)
		preSign1Parties[i] = P
	}
	// var presign1Ended int32

	var wg sync.WaitGroup
	for i, party := range preSign1Parties {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
		fmt.Printf("Party%2d [presign 1]: initialized and running...\n", i)
	}
	wg.Wait()

	// Fetching messages produced by Presign 1
	if err := fetchingMessages(ctx, dumpCh, r1dumps, N, errCh, outCh, &r1msgs, nil, nil, nil, nil, nil, nil, 2); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 1 all done. Received dump data from %d participants\n", N)

	// @Presign 2
	preSign1Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign 2]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r1dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSign2Parties[i] = P.(*LocalParty)
	}

	// Update parties@Presign2 by r1msgs
	fmt.Printf("Parties consuming r1msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSign2Parties, r1msgs, updater, errCh); err != nil {
		t.Error(err)
	}

	// Fetching messages produced by Presign 2
	if err := fetchingMessages(ctx, dumpCh, r2dumps, N, errCh, outCh, &r2msgs, nil, nil, nil, nil, nil, nil, 1); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 2 all done. Received dump data from %d participants\n", N)

	// @Presign 3
	preSign2Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign 3]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r2dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSign3Parties[i] = P.(*LocalParty)
	}

	// Update parties@Presign3 by r2msgs
	fmt.Printf("Parties consuming r2msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSign3Parties, r2msgs, updater, errCh); err != nil {
		t.Error(err)
	}

	// Fetching messages produced by Presign 3
	if err := fetchingMessages(ctx, dumpCh, r3dumps, N, errCh, outCh, &r3msgs, nil, nil, nil, nil, nil, nil, 1); err != nil {
		t.Error(err)
	}
	fmt.Printf("Presign 3 all done. Received dump data from %d participants\n", N)

	// @Presign out
	preSign3Parties = nil
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign out]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r3dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		preSignOutParties[i] = P.(*LocalParty)
	}

	// Update parties@PresignOut by r3msgs
	fmt.Printf("Parties consuming r3msgs and run... \n")
	if err := updatePartiesByMessages(ctx, preSignOutParties, r3msgs, updater, errCh); err != nil {
		t.Error(err)
	}

	var presignOutEnded int32
presignOutLoop:
	for {
		// fmt.Printf("Presignout generating presig...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case du := <-dumpCh:
			i := du.UnmarshalIndex()
			r4dumps[i] = du
			atomic.AddInt32(&presignOutEnded, 1)
			if atomic.LoadInt32(&presignOutEnded) == int32(len(signPIDs)) {
				t.Logf("Presign_out Done. Received dump data from %d participants", presignOutEnded)

				goto identification
			}

		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presignOutLoop

		case predata := <-preSigCh:
			preSigs[predata.UnmarshalIndex()] = predata
			i := predata.UnmarshalIndex()
			ssid := new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64()
			fmt.Printf("Party%2d [presign out]: done and stored preSig(%d) \n", i, ssid)
		}
	}

identification:
	// Presign out
	for i := 0; i < N; i++ {
		fmt.Printf("Party%2d [presign identification]: restored \n", i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, true, 0)

		P, err := RestoreLocalParty(ctx, params, keys[i], r4dumps[i], outCh, preSigCh, dumpCh)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		presignIdentificationParties[i] = P.(*LocalParty)
	}
	for i, party := range presignIdentificationParties {
		go func(P *LocalParty) {
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
		fmt.Printf("Party%2d [presign identification]: running...\n", i)
	}

	var identificationEnded int32
	for {
		// fmt.Printf("Signing selecting messages...ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range presignIdentificationParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, presignIdentificationParties[dest[0].Index], msg, errCh)
			}

		case <-dumpCh:
			atomic.AddInt32(&identificationEnded, 1)
			if atomic.LoadInt32(&identificationEnded) == int32(len(signPIDs)) {
				t.Logf("Identification Done. Received from %d participants", identificationEnded)

				return
			}
		}
	}
}

func TestE2EConcurrentHD(t *testing.T) {
	ctx := context.Background()
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
	outCh := make(chan tss.Message, len(signPIDs)*2)
	endCh := make(chan *PreSignatureData, len(signPIDs))
	dumpCh := make(chan *LocalDumpPB, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		// Use master key vault
		P := NewLocalParty(params, keys[i], outCh, endCh, dumpCh).(*LocalParty)
		parties = append(parties, P)
	}
	var wg sync.WaitGroup
	for _, party := range parties {
		wg.Add(1)
		go func(P *LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	preSigDatas := make([]*PreSignatureData, len(signPIDs))

	var presignEnded int32
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
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, parties[dest[0].Index], msg, errCh)
			}

		case predata := <-endCh:
			atomic.AddInt32(&presignEnded, 1)
			preSigDatas[predata.UnmarshalIndex()] = predata
			t.Logf("%d ssid: %d", predata.UnmarshalIndex(), new(big.Int).SetBytes(predata.UnmarshalSsid()).Int64())
			if atomic.LoadInt32(&presignEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received presignature data from %d participants", presignEnded)

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
	sdumpCh := make(chan *sign.LocalDumpPB, len(signPIDs))

	updater = test.SharedPartyUpdater

	// Derive chlid key vault
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)
	il, _, errorDerivation := DerivingPubkeyFromPath(keys[0].ECDSAPub, chainCode, []uint32{12, 209, 3}, tss.S256())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")
	keyDerivationDelta := il

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)

		// keys[i] is master key, keyDerivationDelta is child key delta relative to master key
		P := sign.NewLocalParty(preSigDatas[i], big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, sigCh, sdumpCh).(*sign.LocalParty)
		signParties = append(signParties, P)
	}
	wg = sync.WaitGroup{}
	for _, party := range signParties {
		wg.Add(1)
		go func(P *sign.LocalParty) {
			defer wg.Done()
			if err := P.Start(ctx); err != nil {
				errCh <- err
			}
		}(party)
	}
	wg.Wait()

	var signEnded int32
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
					go updater(ctx, P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(ctx, signParties[dest[0].Index], msg, errCh)
			}

		case <-sigCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", signEnded)

				return
			}
		}
	}
}
