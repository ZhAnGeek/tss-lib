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

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	cmts "github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

// round 1 represents round 1 of the keygen part of the Schnorr TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
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

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true
	ids := round.Parties().IDs().Keys()
	round.save.ShareID = ids[i]
	round.save.Ks = ids

	round.temp.ssidNonce = new(big.Int).SetInt64(int64(0))
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.ssid = ssid

	// calculate "partial" key share u1i
	u1i := common.GetRandomPositiveInt(round.Params().EC().Params().N)
	round.temp.u1i = u1i

	// compute the vss shares1
	vs1, shares1, err := vss.Create(round.Params().EC(), round.Threshold(), u1i, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// make commitment -> (C, D)
	pGFlat1, err := crypto.FlattenECPoints(vs1)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt1 := cmts.NewHashCommitment(ctx, pGFlat1...)

	// calculate "partial" key share u1i
	u2i := common.GetRandomPositiveInt(round.Params().EC().Params().N)
	round.temp.u2i = u2i

	// compute the vss shares1
	vs2, shares2, err := vss.Create(round.Params().EC(), round.Threshold(), u2i, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// make commitment -> (C, D)
	pGFlat2, err := crypto.FlattenECPoints(vs2)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt2 := cmts.NewHashCommitment(ctx, pGFlat2...)

	round.save.ShareID = ids[i]
	round.temp.vs1 = vs1
	round.temp.shares1 = shares1
	round.temp.deCommitPolyG1 = cmt1.D
	round.temp.vs2 = vs2
	round.temp.shares2 = shares2
	round.temp.deCommitPolyG2 = cmt2.D

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), cmt1.C, cmt2.C)
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.KGCs1 {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			ret = false
			continue
		}
		if round.temp.KGCs2[j] == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
