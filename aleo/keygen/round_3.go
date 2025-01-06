// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon4"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

func (round *round3) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round3")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round3")

	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	i := round.PartyID().Index
	round.ok[i] = true
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())

	// calculate sigShare
	sigShare := round.temp.shares1[i].Share
	for j := range Ps {
		if j == i {
			continue
		}
		sigShare = new(big.Int).Add(sigShare, round.temp.r2msg1SigShares[j])
	}

	// calculate rShare
	rShare := round.temp.shares2[i].Share
	for j := range Ps {
		if j == i {
			continue
		}
		rShare = new(big.Int).Add(rShare, round.temp.r2msg1RShares[j])
	}

	Vc1 := make(vss.Vs, round.Threshold()+1)
	for c := range Vc1 {
		Vc1[c] = round.temp.vs1[c] // ours
	}

	Vc2 := make(vss.Vs, round.Threshold()+1)
	for c := range Vc2 {
		Vc2[c] = round.temp.vs2[c] // ours
	}

	// check shares1
	for j, Pj := range Ps {
		if j == i {
			continue
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		KGCj := round.temp.KGCs1[j]
		KGDj := round.temp.r2msg2SigDecommit[j]
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
			Vc1[c], err = Vc1[c].Add(PjVs[c])
			if err != nil {
				return round.WrapError(errors.New("adding PjVs[c] to Vc1[c] resulted in a point not on the curve"), Pj)
			}
		}

		proof := round.temp.r2msg2SigProof[j]
		ok = proof.Verify(ctx, ContextJ, PjVs[0], rejectionSample)
		if !ok {
			return round.WrapError(errors.New("failed to verify schnorr proof"), Pj)
		}

		PjShare := vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     round.temp.r2msg1SigShares[j],
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(errors.New("VSS verify failed"), Pj)
		}

		KGCj = round.temp.KGCs2[j]
		KGDj = round.temp.r2msg2RDecommit[j]
		cmtDeCmt = commitments.HashCommitDecommit{C: KGCj, D: KGDj}
		ok, flatPolyGs = cmtDeCmt.DeCommit(ctx, (round.Threshold()+1)*2)
		if !ok || flatPolyGs == nil {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		PjVs, err = crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs)
		if err != nil || len(PjVs) != round.Threshold()+1 {
			return round.WrapError(errors.New("de-commitment failed"), Pj)
		}
		for c := 0; c <= round.Threshold(); c++ {
			Vc2[c], err = Vc2[c].Add(PjVs[c])
			if err != nil {
				return round.WrapError(errors.New("adding PjVs[c] to Vc2[c] resulted in a point not on the curve"), Pj)
			}
		}

		proof = round.temp.r2msg2RProof[j]
		ok = proof.Verify(ctx, ContextJ, PjVs[0], rejectionSample)
		if !ok {
			return round.WrapError(errors.New("failed to verify schnorr proof"), Pj)
		}

		PjShare = vss.Share{
			Threshold: round.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     round.temp.r2msg1RShares[j],
		}
		if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok {
			return round.WrapError(errors.New("VSS verify failed"), Pj)
		}
	}

	// compute and SAVE the public key
	PkSig, err := crypto.NewECPoint(round.Params().EC(), Vc1[0].X(), Vc1[0].Y())
	if err != nil {
		return round.WrapError(errors.New("pk_sig key is not on the curve"))
	}
	round.save.PkSig = PkSig
	round.save.SkSigShare = new(big.Int).Mod(sigShare, round.EC().Params().N)

	PrSig, err := crypto.NewECPoint(round.Params().EC(), Vc2[0].X(), Vc2[0].Y())
	if err != nil {
		return round.WrapError(errors.New("pr_sig key is not on the curve"))
	}
	round.save.PrSig = PrSig
	round.save.RSigShare = new(big.Int).Mod(rShare, round.EC().Params().N)
	SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{PkSig.X(), PrSig.X()})
	PkPrf := crypto.ScalarBaseMult(round.EC(), SkPrf)

	Address, err := PkSig.Add(PrSig)
	if err != nil {
		return round.WrapError(errors.New("deriving address failed"))
	}
	Address, err = PkPrf.Add(Address)
	if err != nil {
		return round.WrapError(errors.New("deriving address failed"))
	}
	round.save.Address = Address

	// compute BigXj for each Pj
	{
		var err error
		modQ := common.ModInt(round.EC().Params().N)
		for j, Pj := range Ps {
			kj := Pj.KeyInt()
			BigXj := Vc1[0]
			z := common.One
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc1[c].ScalarMult(z))
				if err != nil {
					return round.WrapError(errors.New("adding Vc1[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), Pj)
				}
			}
			round.save.PkSigShares[j] = BigXj

			BigXj = Vc2[0]
			z = common.One
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc2[c].ScalarMult(z))
				if err != nil {
					return round.WrapError(errors.New("adding Vc1[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), Pj)
				}
			}
			round.save.PrSigShares[j] = BigXj
		}
	}

	// PRINT party id & public key
	log.Debug(ctx, "%s public key: %x", round.PartyID(), PkSig)
	round.isFinished = true
	round.end <- round.save
	return nil
}

func (round *round3) CanAccept(_ tss.ParsedMessage) bool {
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
