// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package shared_secret

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func newRound2(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *crypto.ECPoint) tss.Round {
	return &round2{&round1{
		&base{params, key, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 2, false}}}
}

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	A := round.temp.AiB[i]
	g, _ := crypto.NewECPoint(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		eqProof := round.temp.EqProofs[j]
		ok := eqProof.Verify(ctx, round.temp.Ssid, round.EC(), g, round.temp.B, round.temp.BigWs[j], round.temp.AiB[j], common.RejectionSampleV2)
		if !ok {
			return round.WrapError(errors.New("verify error"), Pj)
		}
		var err error
		A, err = A.Add(round.temp.AiB[j])
		if err != nil {
			return round.WrapError(errors.New("failed to gather A"), Pj)
		}
	}

	round.end <- A

	return nil
}

func (round *round2) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round2) NextRound() tss.Round {
	return nil // finished!
}
