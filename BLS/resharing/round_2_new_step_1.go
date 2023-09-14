// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"bytes"
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/common"
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
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		return nil
	}
	round.allNewOK()

	Pi := round.PartyID()
	i := Pi.Index

	// check consistency of SSID
	r1msg := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
	SSID := r1msg.UnmarshalSSID()
	for j, Pj := range round.OldParties().IDs() {
		if j == 0 {
			continue
		}
		msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		SSIDj := msg.UnmarshalSSID()
		if !bytes.Equal(SSID, SSIDj) {
			return round.WrapError(errors.New("ssid mismatch"), Pj)
		}
	}

	// 1. "broadcast" "ACK" members of the OLD committee
	r2msg := NewDGRound2Message(round.OldParties().IDs(), Pi)
	round.temp.dgRound2Messages[i] = r2msg
	round.out <- r2msg

	round.temp.SSID = SSID

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// only the old committee receive in this round
	if !round.ReSharingParams().IsOldCommittee() {
		return true, nil
	}

	// accept messages from new -> old committee
	for j, msg := range round.temp.dgRound2Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.newOK[j] = true
	}

	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
