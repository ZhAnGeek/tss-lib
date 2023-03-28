// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	cmts "github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	"github.com/Safulet/tss-lib-private/tss"
)

// round 1 represents round 1 of the keygen part of the KCDSA TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	round.temp.ssidNonce = new(big.Int).SetInt64(int64(0))
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.ssid = ssid

	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(ctx, round.SafePrimeGenTimeout())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
		round.save.LocalPreParams = *preParams
	}

	// calculate "partial" key share ui, which see as Xi during Mta
	ui := common.GetRandomPositiveInt(round.Params().EC().Params().N)
	round.temp.ui = ui

	ri := common.GetRandomPositiveInt(round.Params().EC().Params().N)
	round.temp.ri = ri

	R, RNonce, err := round.save.PaillierSK.EncryptAndReturnRandomness(ri)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"), Pi)
	}

	X, XNonce, err := round.save.PaillierSK.EncryptAndReturnRandomness(ui)
	if err != nil {
		return round.WrapError(fmt.Errorf("paillier encryption failed"), Pi)
	}
	round.temp.RNonce = RNonce
	round.temp.R = R
	round.temp.RShare = ri

	round.temp.XNonce = XNonce
	round.temp.X = X
	round.temp.XShare = ui

	// compute the vss vs_xshares
	ids := round.Parties().IDs().Keys()

	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(ctx, pGFlat...)

	round.save.ShareID = ids[i]
	round.temp.vs = vs
	round.temp.vsXshares = shares
	round.temp.deCommitPolyG = cmt.D

	// below is for r share
	rvs, rshares, err := vss.Create(round.Params().EC(), round.Threshold(), ri, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// make commitment -> (C, D)
	rpGFlat, err := crypto.FlattenECPoints(rvs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	rcmt := cmts.NewHashCommitment(ctx, rpGFlat...)

	round.temp.rvs = rvs
	round.temp.vsRshares = rshares
	round.temp.rdeCommitPolyG = rcmt.D

	// BROADCAST commitments
	{
		msg := NewKGRound1Message1(round.PartyID(), &round.save.PaillierSK.PublicKey, round.save.PaillierSK.N, round.save.H1i, round.save.H2i, R, X, rcmt.C, cmt.C)
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message1); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.KGCs {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	for j, msg := range round.temp.rKGCs {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
