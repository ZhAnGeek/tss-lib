// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/commitments"
	"github.com/Safulet/tss-lib-private/crypto/mta"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	zkplogstar "github.com/Safulet/tss-lib-private/crypto/zkp/logstar"
	"github.com/Safulet/tss-lib-private/log"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *round3) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	i := round.PartyID().Index
	Pi := round.PartyID()
	round.ok[i] = true

	// calculate xi
	xi := round.temp.vsXshares[i].Share
	for j := range Ps {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r2msg1SharesX[j])
	}

	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c] // ours
	}

	// check vs_xshares
	for j, Pj := range Ps {
		if j == i {
			continue
		}
		ContextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
		KGCj := round.temp.KGCs[j]
		KGDj := round.temp.r2msg2DecommitX[j]
		cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
		ok, flatPolyGs := cmtDeCmt.DeCommit(ctx, (round.Threshold()+1)*2)
		if !ok || flatPolyGs == nil {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
		if err != nil || len(PjVs) != round.Threshold()+1 {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		for c := 0; c <= round.Threshold(); c++ {
			Vc[c], err = Vc[c].Add(PjVs[c])
			if err != nil {
				return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), Pj)
			}
		}

		proof := round.temp.r2msg2ProofX[j]
		ok = proof.Verify(ctx, ContextJ, PjVs[0])
		if !ok {
			return round.WrapError(errors.New("failed to verify schnorr proof"), Pj)
		}

		PjShare := vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     round.temp.r2msg1SharesX[j],
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(errors.New("VSS verify failed"), Pj)
		}
	}

	PubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors.New("public key is not on the curve"))
	}

	needsNeg := PubKey.Y().Bit(0) != 0
	if needsNeg {
		Y2 := new(big.Int).Sub(round.EC().Params().P, PubKey.Y())
		PubKey2, err := crypto.NewECPoint(round.EC(), Vc[0].X(), Y2)
		if err != nil {
			return round.WrapError(err)
		}
		PubKey = PubKey2
	}
	// here pubkey is schnorr pubkey, we are using it in shares, to make sure share not change the Pubkey x ^ -1 G
	round.save.PubKeySchnorr = PubKey

	// which should be negative when mapping to xi
	round.temp.xi = xi

	// compute BigXj for each Pj
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

	rVc := make(vss.Vs, round.Threshold()+1)
	for c := range rVc {
		rVc[c] = round.temp.rvs[c] // ours
	}

	// calculate big r
	for j, Pj := range Ps {
		if j == i {
			continue
		}
		ContextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
		KGCj := round.temp.rKGCs[j]
		KGDj := round.temp.r2msg2DecommitR[j]
		cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
		ok, flatPolyGs := cmtDeCmt.DeCommit(ctx, (round.Threshold()+1)*2)
		if !ok || flatPolyGs == nil {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
		if err != nil || len(PjVs) != round.Threshold()+1 {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		for c := 0; c <= round.Threshold(); c++ {
			rVc[c], err = rVc[c].Add(PjVs[c])
			if err != nil {
				return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), Pj)
			}
		}

		proof := round.temp.r2msg2ProofR[j]
		ok = proof.Verify(ctx, ContextJ, PjVs[0])
		if !ok {
			return round.WrapError(errors.New("failed to verify schnorr proof"), Pj)
		}

		PjShare := vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     round.temp.r2msg1SharesR[j],
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(errors.New("VSS verify failed"), Pj)
		}
	}

	BigR, err := crypto.NewECPoint(round.Params().EC(), rVc[0].X(), rVc[0].Y())
	if err != nil {
		return round.WrapError(errors.New("public key is not on the curve"))
	}
	round.save.BigR = BigR
	// PRINT public key & private share
	log.Debug(ctx, "%s public key: %x", round.PartyID(), PubKey)

	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	BigXShare := crypto.ScalarBaseMult(round.Params().EC(), round.temp.XShare)
	round.temp.BigXShare = BigXShare
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			facProof := round.temp.r2msg1FacProof[j]
			if ok := facProof.Verify(ctx, ContextI, round.EC(), round.save.NTildej[j],
				round.save.PaillierSK.N, round.save.H1i, round.save.H2i); !ok {
				errChs <- round.WrapError(errors.New("pj fac proof verified fail"), Pj)
				return
			}
			Rj := round.temp.r1msg1R[j]

			ContextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
			encProof := round.temp.r2msg1Proof[j]
			encProofVerified := encProof.Verify(ctx, ContextJ, round.EC(), round.save.PaillierPKs[j], round.save.PaillierSK.N, round.save.H1i, round.save.H2i, Rj)
			if !encProofVerified {
				errChs <- round.WrapError(errors.New("rj enc proof verify failed"), Pj)
				return
			}
			rxMta, err := mta.NewMtA(ctx, ContextI, round.EC(), Rj, round.temp.XShare, BigXShare, round.save.PaillierPKs[j], &round.save.PaillierSK.PublicKey, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j])
			if err != nil {
				errChs <- round.WrapError(errors.New("rxMtA failed"), Pi)
				return
			}

			ProofLogstar, err := zkplogstar.NewProof(ctx, ContextI, round.EC(), &round.save.PaillierSK.PublicKey, round.temp.X, BigXShare, g, round.save.NTildej[j], round.save.H1j[j], round.save.H2j[j], round.temp.XShare, round.temp.XNonce)
			if err != nil {
				errChs <- round.WrapError(errors.New("proofLogStar failed"), Pi)
				return
			}

			r3msg := NewKGRound3Message1(Pj, round.PartyID(), BigXShare, rxMta.Dji, rxMta.Fji, rxMta.Proofji, ProofLogstar)
			round.out <- r3msg

			round.temp.RXShareBetas[j] = rxMta.Beta
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msgRXD {
		if round.ok[j] {
			continue
		}
		if msg == nil || round.temp.r3msgBigXShare[j] == nil ||
			round.temp.r3msgRXF[j] == nil ||
			round.temp.r3msgRXProof[j] == nil ||
			round.temp.r3msgProofLogstar[j] == nil {

			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
