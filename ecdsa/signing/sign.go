// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/presigning"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, predata *presigning.PreSignatureData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &sign{&base{params, key, predata, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *sign) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	round.temp.ssid = round.predata.UnmarshalSsid()
	round.temp.KShare = round.predata.UnmarshalKShare()
	round.temp.ChiShare = round.predata.UnmarshalChiShare()
	bigR, err := round.predata.UnmarshalBigR(round.EC())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.BigR = bigR

	// Fig 8. Round 1. compute signature share
	modN := common.ModInt(round.EC().Params().N)
	Rx := round.temp.BigR.X()
	SigmaShare := modN.Add(modN.Mul(round.temp.KShare, round.temp.m), modN.Mul(Rx, round.temp.ChiShare))

	r4msg := NewSignRoundMessage(round.PartyID(), SigmaShare)
	round.out <- r4msg

	round.temp.Rx = Rx
	round.temp.SigmaShare = SigmaShare
	// retire unused variables
	round.temp.r1msgK = nil
	round.temp.r3msgBigDeltaShare = nil
	round.temp.r3msgDeltaShare = nil
	round.temp.r3msgProofLogstar = nil

	return nil
}

func (round *sign) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r4msgSigmaShare {
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

func (round *sign) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRoundMessage); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *sign) NextRound() tss.Round {
	round.started = false
	return &signout{round}
}

func (round *sign) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	BigXs := round.key.BigXj

	// adding the key derivation delta to the xi's
	// Suppose x has shamir shares x_0,     x_1,     ..., x_n
	// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
	mod := common.ModInt(round.Params().EC().Params().N)
	xi = mod.Add(round.temp.keyDerivationDelta, xi)
	round.key.Xi = xi

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, BigWs := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

	round.temp.w = wi
	round.temp.BigWs = BigWs
	return nil
}
