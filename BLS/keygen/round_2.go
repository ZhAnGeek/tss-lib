// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	zkpsch "github.com/Safulet/tss-lib-private/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round2")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round2")

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// p2p send share ij to Pj
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), round.temp.shares[j])
		round.out <- r2msg1
	}
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proof, err := zkpsch.NewProof(ctx, ContextI, round.temp.vs[0], round.temp.ui, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG, proof)
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.r2msg1Shares {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			ret = false
			continue
		}
		if round.temp.r2msg2Decommit[j] == nil || round.temp.r2msg2Proof[j] == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}