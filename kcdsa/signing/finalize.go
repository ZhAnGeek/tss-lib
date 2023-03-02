// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *finalization) VerirySig(ctx context.Context, s *big.Int, e *big.Int, m []byte, pubkey *crypto.ECPoint) bool {
	sY := pubkey.ScalarMult(s)
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	eG := g.ScalarMult(e)
	// if pk is not negative, then eG should negate
	needsNeg := pubkey.Y().Bit(0) != 1
	if needsNeg {
		Y2 := new(big.Int).Sub(round.EC().Params().P, eG.Y())
		eG2, err := crypto.NewECPoint(round.EC(), eG.X(), Y2)
		if err != nil {
			return false
		}
		eG = eG2
	}

	W, _ := sY.Add(eG)
	mHash := sha256.Sum256(m)
	mHashPkBytes := append(mHash[:], W.X().Bytes()...)
	e2Bytes := sha256.Sum256(mHashPkBytes)

	// e1 == e2
	return e.Cmp(new(big.Int).SetBytes(e2Bytes[:])) == 0
}

func (round *finalization) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// count k * x
	modN := common.ModInt(new(big.Int).Set(round.EC().Params().N))
	sumKXShare := round.temp.KXShare
	sumBigKxShare := round.temp.BigKXShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		var err error
		message := round.temp.signRound5Messages[j].Content().(*SignRound5Message1)
		kxShare := message.UnmarshalKXShare()
		bigKxShare, err := message.UnmarshalBigKXShare(round.EC())
		if err != nil {
			return round.WrapError(errors.New("can not add rx share"))
		}
		sumKXShare = modN.Add(sumKXShare, kxShare)
		sumBigKxShare, err = sumBigKxShare.Add(bigKxShare)
		if err != nil {
			return round.WrapError(errors.New("can not add rx share"))
		}
	}
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	bigRXShareCount := g.ScalarMult(sumKXShare)
	if !sumBigKxShare.Equals(bigRXShareCount) {
		return round.WrapError(errors.New("share not equal failed"))
	}

	sBytes := sumKXShare.Bytes()
	eBytes := round.temp.e.Bytes()

	// save the signature for final output
	round.data.R = sBytes
	round.data.S = eBytes
	round.data.Signature = append(sBytes, eBytes...)
	round.data.M = round.temp.m

	ok := round.VerirySig(ctx, sumKXShare, round.temp.e, round.temp.m, round.key.PubKey)
	if !ok {
		return round.WrapError(errors.New("signature verification failed"), round.PartyID())
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
