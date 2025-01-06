// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon4"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *round5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round5")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round5")

	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	if round.IsNewCommittee() {
		// for this P: SAVE data
		round.save.PkSigShares = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.SkSigShare = round.temp.newXi
		round.save.Ks = round.temp.newKs

		// for this P: SAVE data
		round.save.PrSigShares = round.temp.rNewBigXjs
		round.save.RSigShare = round.temp.rNewXi

		PkSig := round.save.PkSig
		PrSig := round.save.PrSig
		SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{PkSig.X(), PrSig.Y()})
		PkPrf := crypto.ScalarBaseMult(round.EC(), SkPrf)

		Address, err := PkSig.Add(PrSig)
		if err != nil {
			return round.WrapError(errors.New("deriving address failed"))
		}
		Address, err = PkPrf.Add(Address)
		if err != nil {
			return round.WrapError(errors.New("deriving address failed"))
		}
		round.save.Address = Address
	} else if round.IsOldCommittee() {
		round.input.SkSigShare.SetInt64(0)
		round.input.RSigShare.SetInt64(0)
	}
	round.isFinished = true
	round.end <- round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
