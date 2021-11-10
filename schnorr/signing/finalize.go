// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func VerirySig(ec elliptic.Curve, R *crypto.ECPoint, z *big.Int, M *big.Int, Y *crypto.ECPoint) bool {
	c := common.SHA512_256i(R.X(), R.Y(), Y.X(), Y.Y(), M)
	R2, err := crypto.ScalarBaseMult(ec, z).Add(Y.ScalarMult(new(big.Int).Neg(c)))
	if err != nil {
		return false
	}
	return R2.Equals(R)
}

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	sumZ := round.temp.zi
	modN := common.ModInt(round.EC().Params().N)
	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		zj := r3msg.UnmarshalZi()

		LHS := crypto.ScalarBaseMult(round.EC(), zj)
		RHS := round.key.BigXj[j].ScalarMult(round.temp.c)
		if !LHS.Equals(RHS) {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		sumZ = modN.Add(sumZ, zj)
	}

	// save the signature for final output
	//round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumZ.Bytes()[:]...)
	round.data.R = append(round.temp.R.X().Bytes(), round.temp.R.Y().Bytes()...)
	round.data.S = sumZ.Bytes()
	round.data.M = round.temp.m

	ok := VerirySig(round.EC(), round.temp.R, sumZ, round.temp.M, round.key.PubKey)
	if !ok {
		return round.WrapError(errors.New("signature verification failed"))
	}

	//pk := edwards.PublicKey{
	//	Curve: round.EC(),
	//	X:     round.key.PubKey.X(),
	//	Y:     round.key.PubKey.Y(),
	//}

	//ok := edwards.Verify(&pk, round.temp.m, round.temp.r, s)
	round.end <- *round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
