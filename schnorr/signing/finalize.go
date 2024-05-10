// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/schnorr/signing/btc"
	"github.com/Safulet/tss-lib-private/schnorr/signing/mina"
	"github.com/Safulet/tss-lib-private/schnorr/signing/zil"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"
)

func getSignature(r []byte, s []byte) []byte {
	ret := make([]byte, 64)
	copy(ret[32-len(r):], r)
	copy(ret[64-len(s):], s)
	return ret
}

func (round *finalization4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	_, span := tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	sumZ := round.temp.zi
	modQ := common.ModInt(round.EC().Params().N)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		round.ok[j] = true
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		zj := r3msg.UnmarshalZi()

		LHS := crypto.ScalarBaseMult(round.EC(), zj)
		negC := round.temp.c
		if round.Network() == tss.ZIL {
			negC = modQ.Sub(round.EC().Params().N, round.temp.c)
		}
		var RHS *crypto.ECPoint
		var err error
		if round.Network() == tss.BTC && round.temp.negPrivateKey == true {
			RHS, err = round.temp.Rjs[j].Sub(round.temp.bigWs[j].ScalarMult(negC))
		} else {
			RHS, err = round.temp.Rjs[j].Add(round.temp.bigWs[j].ScalarMult(negC))
		}
		if err != nil {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		if !LHS.Equals(RHS) {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		sumZ = modQ.Add(sumZ, zj)
	}
	if round.temp.KeyDerivationDelta != nil {
		sumZDelta := modQ.Mul(round.temp.c, round.temp.KeyDerivationDelta)
		if round.Network() == tss.ZIL || (round.Network() == tss.BTC && round.temp.negPrivateKey) {
			sumZ = modQ.Sub(sumZ, sumZDelta)
		} else {
			sumZ = modQ.Add(sumZ, sumZDelta)
		}
	}
	if sumZ.Cmp(zero) == 0 {
		return round.WrapError(errors.New("sumZ cannot be zero"))
	}

	// save the signature for final output
	if round.Network() == tss.ZIL {
		round.data.R = round.temp.c.Bytes()
	} else {
		round.data.R = round.temp.R.X().Bytes()
	}
	round.data.S = sumZ.Bytes()
	round.data.M = common.PadToLengthBytesInPlace(round.temp.m, 32)
	round.data.Signature = getSignature(round.data.R, round.data.S)

	var ok bool
	switch round.Network() {
	case tss.MINA:
		ok = mina.SchnorrVerify(round.EC(), round.temp.pubKeyDelta, round.temp.m, round.data.Signature) == nil
	case tss.ZIL:
		ok = zil.SchnorrVerify(round.EC(), round.temp.pubKeyDelta, round.temp.m, round.data.Signature) == nil
	default:
		ok = btc.SchnorrVerify(round.EC(), round.temp.pubKeyDelta, round.data.M, round.data.Signature) == nil
	}
	if !ok {
		return round.WrapError(errors.New("signature verification failed"), round.PartyID())
	}
	round.isFinished = true
	round.end <- round.data

	return nil
}

func (round *finalization4) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization4) NextRound() tss.Round {
	return nil // finished!
}
