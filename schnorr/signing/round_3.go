// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	round.temp.Djs[i] = round.temp.pointDi
	round.temp.Ejs[i] = round.temp.pointEi
	// check proofs
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 4 {
			return round.WrapError(errors.New("length of de-commitment should be 4"))
		}

		pointDj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Dj)"), Pj)
		}
		proofD, err := r2msg.UnmarshalZKProofD(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Dj proof"), Pj)
		}
		ok = proofD.Verify(pointDj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Dj"), Pj)
		}
		round.temp.Djs[j] = pointDj

		pointEj, err := crypto.NewECPoint(round.Params().EC(), coordinates[2], coordinates[3])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Ej)"), Pj)
		}
		proofE, err := r2msg.UnmarshalZKProofE(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Ej proof"), Pj)
		}
		ok = proofE.Verify(pointEj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Ej"), Pj)
		}
		round.temp.Ejs[j] = pointEj
	}

	// compute Rj
	M := new(big.Int).SetBytes(round.temp.m)

	DjFlat, err := crypto.FlattenECPoints(round.temp.Djs)
	if err != nil {
		return round.WrapError(errors.New("failed to flattern Djs"), round.PartyID())
	}
	EjFlat, err := crypto.FlattenECPoints(round.temp.Ejs)
	if err != nil {
		return round.WrapError(errors.New("failed to flattern Ejs"), round.PartyID())
	}
	DEFlat := append(DjFlat, EjFlat...)

	for j, Pj := range round.Parties().IDs() {
		rho := common.SHA512_256i(append(DEFlat, M, big.NewInt(int64(j)))...)
		Rj, err := round.temp.Djs[j].Add(round.temp.Ejs[j].ScalarMult(rho))
		if err != nil {
			return round.WrapError(errors.New("error in computing Ri"), Pj)
		}
		round.temp.Rjs[j] = Rj
		round.temp.rhos[j] = rho
	}

	R := round.temp.Rjs[i]
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		var err error
		R, err = R.Add(round.temp.Rjs[j])
		if err != nil {
			return round.WrapError(errors.New("error in computing R"), Pj)
		}
	}

	c := common.SHA512_256i(R.X(), R.Y(), round.key.PubKey.X(), round.key.PubKey.Y(), M)

	Y2 := round.temp.bigWs[i]
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		Y2, _ = Y2.Add(round.temp.bigWs[j])

	}
	
	modQ := common.ModInt(round.EC().Params().N) // TODO
	zi := modQ.Add(round.temp.di, modQ.Mul(round.temp.ei, round.temp.rhos[i]))
	zi = modQ.Add(zi, modQ.Mul(round.temp.wi, c))

	round.temp.zi = zi
	round.temp.c = c
	round.temp.R = R
	// broadcast zi to other parties
	r3msg := NewSignRound3Message(round.PartyID(), zi)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
