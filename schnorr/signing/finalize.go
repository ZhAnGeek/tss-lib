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

func VerirySig(ec elliptic.Curve, R *crypto.ECPoint, z *big.Int, m []byte, Y *crypto.ECPoint) bool {
	M := new(big.Int).SetBytes(m)
	c := common.SHA512_256i(R.X(), R.Y(), Y.X(), Y.Y(), M)
	LHS := crypto.ScalarBaseMult(ec, z)
	RHS, err := R.Add(Y.ScalarMult(c))
	if err != nil {
		return false
	}
	return LHS.Equals(RHS)
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
	modQ := common.ModInt(round.EC().Params().N)
	for j, Pj := range round.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		zj := r3msg.UnmarshalZi()

		LHS := crypto.ScalarBaseMult(round.EC(), zj)
		RHS, err := round.temp.Rjs[j].Add(round.temp.bigWs[j].ScalarMult(round.temp.c))
		if err != nil {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		if !LHS.Equals(RHS) {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		sumZ = modQ.Add(sumZ, zj)
	}

	// save the signature for final output
	//round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumZ.Bytes()[:]...)
	round.data.R = append(round.temp.R.X().Bytes(), round.temp.R.Y().Bytes()...)
	round.data.S = sumZ.Bytes()
	round.data.M = round.temp.m

	ok := VerirySig(round.EC(), round.temp.R, sumZ, round.temp.m, round.key.PubKey)
	if !ok {
		return round.WrapError(errors.New("signature verification failed"), round.PartyID())
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