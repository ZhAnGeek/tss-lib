// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound3(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}
}

func (round *presign3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 3.1 verify proofs received and decrypt alpha share of MtA output
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		BigGammaSharej := round.temp.r2msgBigGammaShare[j]

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			DeltaD := round.temp.r2msgDeltaD[j]
			DeltaF := round.temp.r2msgDeltaF[j]
			proofAffgDelta := round.temp.r2msgDeltaProof[j]
			ok := proofAffgDelta.Verify([]byte("TODO"), round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, DeltaD, DeltaF, BigGammaSharej)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg delta"))
				return
			}
			AlphaDelta, err := round.key.PaillierSK.Decrypt(DeltaD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.DeltaShareAlphas[j] = AlphaDelta
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ChiD := round.temp.r2msgChiD[j]
			ChiF := round.temp.r2msgChiF[j]
			proofAffgChi := round.temp.r2msgChiProof[j]
			ok := proofAffgChi.Verify([]byte("TODO"), round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, ChiD, ChiF, round.temp.BigWs[j])
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg chi"))
				return
			}
			AlphaChi, err := round.key.PaillierSK.Decrypt(ChiD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.ChiShareAlphas[j] = AlphaChi
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			proofLogstar := round.temp.r2msgProofLogstar[j]
			Gj := round.temp.r1msgG[j]
			ok := proofLogstar.Verify([]byte("TODO"), round.EC(), round.key.PaillierPKs[j], Gj, BigGammaSharej, g, round.key.NTildei, round.key.H1i, round.key.H2i)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify logstar"))
				return
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round3: failed to verify proofs"), culprits...)
	}

	// Fig 7. Round 3.2 accumulate results from MtA
	BigGamma := round.temp.BigGammaShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		BigGammaShare := round.temp.r2msgBigGammaShare[j]
		var err error
		BigGamma, err = BigGamma.Add(BigGammaShare)
		if err != nil {
			return round.WrapError(errors.New("round3: failed to collect BigGamma"))
		}
	}
	BigDeltaShare := BigGamma.ScalarMult(round.temp.KShare)

	modN := common.ModInt(round.EC().Params().N)
	DeltaShare := modN.Mul(round.temp.KShare, round.temp.GammaShare)
	ChiShare := modN.Mul(round.temp.KShare, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareAlphas[j])
		DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareBetas[j])

		ChiShare = modN.Add(ChiShare, round.temp.ChiShareAlphas[j])
		ChiShare = modN.Add(ChiShare, round.temp.ChiShareBetas[j])
	}

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg = sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ProofOut := make(chan *zkplogstar.ProofLogstar, 1)
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ProofLogstar, err := zkplogstar.NewProof([]byte("TODO"), round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, BigDeltaShare, BigGamma, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.KShare, round.temp.KNonce)
			if err != nil {
				errChs <- round.WrapError(errors.New("proof generation failed"))
			}
			ProofOut <- ProofLogstar
		}(j, Pj)

		ProofLogstar := <-ProofOut
		r3msg := NewPreSignRound3Message(Pj, round.PartyID(), DeltaShare, BigDeltaShare, ProofLogstar)
		round.out <- r3msg
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	round.temp.DeltaShare = DeltaShare
	round.temp.ChiShare = ChiShare
	round.temp.BigDeltaShare = BigDeltaShare
	round.temp.BigGamma = BigGamma
	// retire unused variables
	round.temp.w = nil
	round.temp.BigWs = nil
	round.temp.GammaShare = nil
	round.temp.BigGammaShare = nil
	round.temp.K = nil
	round.temp.KNonce = nil
	round.temp.DeltaShareBetas = nil
	round.temp.ChiShareBetas = nil
	round.temp.DeltaShareAlphas = nil
	round.temp.ChiShareAlphas = nil
	round.temp.r1msgG = nil
	round.temp.r2msgDeltaD = nil
	round.temp.r2msgDeltaF = nil
	round.temp.r2msgChiD = nil
	round.temp.r2msgChiF = nil
	round.temp.r2msgDeltaProof = nil
	round.temp.r2msgChiProof = nil
	round.temp.r2msgProofLogstar = nil

	return nil
}

func (round *presign3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msgDeltaShare {
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

func (round *presign3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign3) NextRound() tss.Round {
	round.started = false
	return &sign4{round}
}
