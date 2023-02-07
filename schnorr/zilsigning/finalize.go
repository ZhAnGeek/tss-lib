// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zilsigning

import (
	"context"
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func VerifySig(ec elliptic.Curve, e, s *big.Int, m []byte, Y *crypto.ECPoint) bool {
	one := big.NewInt(1)
	N := ec.Params().N
	if e.Cmp(one) < 0 {
		return false
	}
	if s.Cmp(one) < 0 {
		return false
	}
	if e.Cmp(N) >= 0 {
		return false
	}
	if s.Cmp(N) >= 0 {
		return false
	}
	R2 := crypto.ScalarBaseMult(ec, s)
	tmp := Y.ScalarMult(e)
	R2, err := R2.Add(tmp)
	if err != nil {
		return false
	}
	e2_ := schnorrHash(getCompressedBytes(R2), getCompressedBytes(Y), m)
	e2 := new(big.Int).SetBytes(e2_)
	return e.Cmp(e2) == 0
}

func (round *finalization) Start(ctx context.Context) *tss.Error {
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
		negC := modQ.Sub(round.EC().Params().N, round.temp.c)
		RHS, err := round.temp.Rjs[j].Add(round.temp.bigWs[j].ScalarMult(negC))
		if err != nil {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		if !LHS.Equals(RHS) {
			return round.WrapError(errors.New("zj check failed"), Pj)
		}
		sumZ = modQ.Add(sumZ, zj)
	}

	// save the signature for final output
	// round.data.R = round.temp.R.X().Bytes()
	// round.data.S = sumZ.Bytes()
	// round.data.Signature = append(round.temp.R.X().Bytes(), sumZ.Bytes()...)
	round.data.R = round.temp.c.Bytes()
	round.data.S = sumZ.Bytes()
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.M = round.temp.m

	err := ZILSchnorrVerify(round.key.PubKey, round.data.M, round.data.Signature)
	if err != nil {
		return round.WrapError(errors.New("signature verification failed"))
	}

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
