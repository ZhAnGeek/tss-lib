// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

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
	ContextI := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(i)))

	// 1. store r1 message pieces
	sumV1 := round.temp.pointV1
	sumV2 := round.temp.pointV2
	pointG := crypto.ScalarBaseMult(round.EC(), common.One)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		msg := round.temp.signRound1Messages[j]
		r1msg := msg.Content().(*SignRound1Message)
		round.temp.cjs[j] = r1msg.UnmarshalCommitment()
		V1, err := r1msg.UnmarshalPointV1(round.EC())
		if err != nil {
			return round.WrapError(err, Pj)
		}
		proof1, err := r1msg.UnmarshalProof1()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		ok := proof1.Verify(ctx, ContextJ, round.EC(), pointG, round.temp.pointH1, round.temp.bigW1s[j], V1, common.RejectionSample)
		if !ok {
			return round.WrapError(errors.New("verify proof 1 failed"), Pj)
		}
		sumV1, err = V1.Add(sumV1)
		if err != nil {
			return round.WrapError(errors.New("sum V1"), Pj)
		}
		V2, err := r1msg.UnmarshalPointV2(round.EC())
		if err != nil {
			return round.WrapError(err, Pj)
		}
		proof2, err := r1msg.UnmarshalProof2()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		ok = proof2.Verify(ctx, ContextJ, round.EC(), pointG, round.temp.pointH2, round.temp.bigW2s[j], V2, common.RejectionSample)
		if !ok {
			return round.WrapError(errors.New("verify proof 2 failed"), Pj)
		}
		sumV2, err = V2.Add(sumV2)
		if err != nil {
			return round.WrapError(errors.New("sum V2"), Pj)
		}
	}

	V, err := sumV1.Add(sumV2)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	skTag := V.X()
	round.temp.skTag = skTag

	// 2. compute Schnorr prove
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proofD, err := zkpsch.NewProof(ctx, ContextI, round.temp.pointDi, round.temp.di, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	proofE, err := zkpsch.NewProof(ctx, ContextI, round.temp.pointEi, round.temp.ei, rejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3. BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewSignRound2Message(round.PartyID(), round.temp.deCommit, proofD, proofE, skTag)
	round.temp.signRound2Messages[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound2Messages {
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

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
