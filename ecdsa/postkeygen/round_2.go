// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/crypto/paillier"
	zkpmod "github.com/Safulet/tss-lib-private/crypto/zkp/mod"
	zkpprm "github.com/Safulet/tss-lib-private/crypto/zkp/prm"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	ids := round.Parties().IDs().Keys()
	round.save.ShareID = ids[i]
	round.save.Ks = ids
	round.ok[i] = true

	round.temp.ssidNonce = new(big.Int).SetInt64(int64(0))
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.ssid = ssid

	var preParams *keygen.LocalPreParams
	if round.save.LocalPreParams.Validate() {
		preParams = &round.save.LocalPreParams
		log.Debug(ctx, "pre params valid")
	} else {
		preParams, err = keygen.GeneratePreParams(ctx, round.SafePrimeGenTimeout())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	round.save.LocalPreParams = *preParams
	round.save.H1j[i] = preParams.H1i
	round.save.H2j[i] = preParams.H2i
	round.save.NTildej[i] = preParams.PaillierSK.N
	round.save.PaillierPKs[i] = &paillier.PublicKey{N: preParams.PaillierSK.N}

	Phi := new(big.Int).Mul(new(big.Int).Lsh(round.save.P, 1), new(big.Int).Lsh(round.save.Q, 1))
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	proofPrm, err := zkpprm.NewProof(ctx, ContextI, round.save.H1i, round.save.H2i, round.save.PaillierSK.N, Phi, round.save.Beta)
	if err != nil {
		return round.WrapError(errors.New("create proofPrm failed"), Pi)
	}

	// Fig 5. Round 3.2 / Fig 6. Round 3.2 proofs
	SP := new(big.Int).Add(new(big.Int).Lsh(round.save.P, 1), one)
	SQ := new(big.Int).Add(new(big.Int).Lsh(round.save.Q, 1), one)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proofMod, err := zkpmod.NewProof(ctx, ContextI, round.save.PaillierSK.N, SP, SQ, rejectionSample)
	if err != nil {
		return round.WrapError(errors.New("create proofMod failed"), Pi)
	}

	// BROADCAST Paillier PK
	{
		msg := NewKGRound2Message1(round.PartyID(), &round.save.PaillierSK.PublicKey, round.save.PaillierSK.N, round.save.H1i, round.save.H2i, proofPrm, proofMod)
		round.out <- msg
	}
	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.ProofPrms {
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

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
