// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon4"
	"github.com/Safulet/tss-lib-private/v2/aleo/signing"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	testThreshold = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	ctx := context.Background()
	setUp(log.DebugLevel)
	ec := tss.EdBls12377()

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1) // , testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *signing.RequestOut, len(signPIDs))

	updater := test.SharedPartyUpdater

	nonce := big.NewInt(200)
	// no ckd (0, 0)
	// signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	// ckd (42, 139)
	signInputsStr := `{"signer":"aleo1vdlwj6u030w4dra2su3trgnx2mh339hnrxtkwvt44nd49m6l65xq2m24kc","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["c7fcd2d71e17bbad1e550f456245cdacde312ce7332ecf62ea58b7a5debfaa09","f1020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs signing.RInputs
	err = json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	pointUs := signing.ComputeRecordsH(signInputs)
	// init the parties
	wg := sync.WaitGroup{}
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(ec, p2pCtx, signPIDs[i], len(signPIDs), threshold, false, 0)
		delta1 := new(big.Int).SetUint64(42)
		delta2 := new(big.Int).SetUint64(139)
		P := signing.NewLocalParty(nonce, pointUs, signInputs, params, keys[i], delta1, delta2, outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		wg.Add(1)
		go func(P *signing.LocalParty) {
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

func TestPaseReqInputs(t *testing.T) {
	jsonStr := `{
	"signer": "aleo1l2sdtvqqg3ahcrcxljcd3rc2u3glghg3nydgdze3nnjxs7sq4szqr9xgur",
	"function_id": "f5a4f3c82da25e40879ab0c39fe6f2c24417ed61d9f9045e88bd2f6905fb6d11",
	"inputs": [{
		"fields": ["00f403509c293e026569508259a428e5edd417a04f3ffbaf0db5ec44e6c8660b", "af6d490b00000000000000000000000000000000000000000000000000000000"],
		"index": 0,
		"input_type": "public"
	}, {
		"fields": ["3000019001000000000000040000000000000000000000000000000000000000"],
		"index": 1,
		"input_type": "public"
	}]
}`
	var res signing.RInputs
	err := json.Unmarshal([]byte(jsonStr), &res)
	assert.NoError(t, err)
	fmt.Println("final:", res)
}

func TestAddress(t *testing.T) {
	setUp(log.DebugLevel)
	ec := tss.EdBls12377()

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1) // , testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))
	PkSig := keys[0].PkSig
	PrSig := keys[0].PrSig

	SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{PkSig.X(), PrSig.X()})
	PkPrf := crypto.ScalarBaseMult(ec, SkPrf)

	Address, err := PkSig.Add(PrSig)
	assert.NoError(t, err)
	Address, err = PkPrf.Add(Address)
	assert.NoError(t, err)

	addr, err := signing.ToAddress(Address)
	assert.NoError(t, err)
	fmt.Println("addr:", addr)
}
