// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs() //TODO
	i := round.PartyID().Index
	round.ok[i] = true

	// calculate xi
	xi := round.temp.shares[i].Share
	for j := range Ps {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r2msg1Shares[j])
	}
	round.save.Xi = new(big.Int).Mod(xi, round.EC().Params().N)

	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c] // ours
	}

	// check shares
	for j, Pj := range Ps {
		if j == i {
			continue
		}
		KGCj := round.temp.KGCs[j]
		KGDj := round.temp.r2msg2Decommit[j]
		cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
		ok, flatPolyGs := cmtDeCmt.DeCommit()
		if !ok || flatPolyGs == nil {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
		if err != nil {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		for c := 0; c <= round.Threshold(); c++ {
			Vc[c], err = Vc[c].Add(PjVs[c])
			if err != nil {
				return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), Pj)
			}
		}

		proof := round.temp.r2msg2Proof[j]
		ok = proof.Verify(PjVs[0])
		if !ok {
			return round.WrapError(errors.New("failed to verify schnorr proof"), Pj)
		}

		PjShare := vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     round.temp.r2msg1Shares[j],
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(errors.New("VSS verify failed"), Pj)
		}
	}

	// compute Xj for each Pj
	{
		var err error
		modQ := common.ModInt(round.EC().Params().N)
		for j, Pj := range Ps {
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), Pj)
				}
			}
			round.save.BigXj[j] = BigXj
		}
	}

	// compute and SAVE the public key
	PubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.PubKey = PubKey

	// PRINT public key & private share
	common.Logger.Debugf("%s public key: %x", round.PartyID(), PubKey)

	round.end <- *round.save
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round3) NextRound() tss.Round {
	return nil // finished!
}