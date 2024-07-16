// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/kcdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the signing part of the KCDSA TSS spec
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round1")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round1")

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	round.temp.ssidNonce = new(big.Int).SetInt64(int64(0))
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.ssid = ssid

	mHash := sha256.Sum256(round.temp.m)
	// mHash
	round.temp.mHash = mHash[:]

	// 1. select ki
	ki := common.GetRandomPositiveInt(round.EC().Params().N)

	// 2. make commitment
	pointKi := crypto.ScalarBaseMult(round.Params().EC(), ki)
	cmt := commitments.NewHashCommitment(ctx, pointKi.X(), pointKi.Y())

	// 3. store k1 message pieces
	round.temp.ki = ki
	round.temp.pointKi = pointKi
	round.temp.deCommit = cmt.D

	// 4. broadcast commitment
	r1msg1 := NewSignRound1Message(round.PartyID(), cmt.C)
	round.temp.signRound1Messages[i] = r1msg1
	round.out <- r1msg1

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, round.key.BigXj, round.key.PubKey, round.key.BigR)

	round.temp.wi = wi
	return nil
}
