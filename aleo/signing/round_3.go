// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"sync"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	zkpeqlog "github.com/Safulet/tss-lib-private/v2/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/trace"
)

const (
	tagNonce = "aleo/tagNonce/v1"
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

	i := round.PartyID().Index
	round.ok[i] = true

	round.temp.Djs[i] = round.temp.pointDi
	round.temp.Ejs[i] = round.temp.pointEi
	// check proofs
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
			msg := round.temp.signRound2Messages[j]
			r2msg := msg.Content().(*SignRound2Message)
			skTagj := r2msg.UnmarshalSkTag()
			if round.temp.skTag.Cmp(skTagj) != 0 {
				errChs <- round.WrapError(errors.New("skTag not match"))
				return
			}
			cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
			ok, coordinates := cmtDeCmt.DeCommit(ctx, 4)
			if !ok {
				errChs <- round.WrapError(errors.New("de-commitment verify failed"))
				return
			}
			if len(coordinates) != 4 {
				errChs <- round.WrapError(errors.New("length of de-commitment should be 4"))
				return
			}

			pointDj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
			if err != nil {
				errChs <- round.WrapError(errors.Wrapf(err, "NewECPoint(Dj)"), Pj)
				return
			}
			proofD, err := r2msg.UnmarshalZKProofD(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to unmarshal Dj proofTvk"), Pj)
				return
			}
			ok = proofD.Verify(ctx, ContextJ, pointDj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to prove Dj"), Pj)
				return
			}
			round.temp.Djs[j] = pointDj

			pointEj, err := crypto.NewECPoint(round.Params().EC(), coordinates[2], coordinates[3])
			if err != nil {
				errChs <- round.WrapError(errors.Wrapf(err, "NewECPoint(Ej)"), Pj)
				return
			}
			proofE, err := r2msg.UnmarshalZKProofE(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to unmarshal Ej proofTvk"), Pj)
				return
			}
			ok = proofE.Verify(ctx, ContextJ, pointEj, rejectionSample)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to prove Ej"), Pj)
				return
			}
			round.temp.Ejs[j] = pointEj
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
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

	BIndexes := make([]*big.Int, 0)
	for j := range round.Parties().IDs() {
		BIndexes = append(BIndexes, big.NewInt(int64(j)))
	}
	// <i, Di, Ei>
	DEFlat := append(BIndexes, DjFlat...) // i, Di
	DEFlat = append(DEFlat, EjFlat...)    // i, Ei

	for j, Pj := range round.Parties().IDs() {
		rho := common.SHA512_256i_TAGGED(ctx, []byte(tagNonce), append(DEFlat, M, big.NewInt(int64(j)))...)
		Rj, err := round.temp.Djs[j].Add(round.temp.Ejs[j].ScalarMult(rho))
		if err != nil {
			return round.WrapError(errors.New("error in computing Ri"), Pj)
		}
		round.temp.Rjs[j] = Rj
		round.temp.rhos[j] = rho
	}

	// compute R
	R := round.temp.Rjs[i]
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		R, err = R.Add(round.temp.Rjs[j])
		if err != nil {
			return round.WrapError(errors.New("error in computing R"), Pj)
		}
	}

	modQ := common.ModInt(round.EC().Params().N)

	// compute ri
	ri := modQ.Add(round.temp.di, modQ.Mul(round.temp.ei, round.temp.rhos[i]))
	tvkShare := round.temp.childAddr.ScalarMult(ri)
	if tvkShare == nil {
		return round.WrapError(errors.New("error in computing tvkShare"), round.PartyID())
	}
	round.temp.tvkShare = tvkShare

	// build shareList and proofList
	pointG := crypto.ScalarBaseMult(round.EC(), common.One)
	shareList := make([]*crypto.ECPoint, 0, 1+len(round.temp.pointUs)*2) // 1+2*len(hPoints)
	proofList := make([]*zkpeqlog.ProofEqLog, 0, 1+len(round.temp.pointUs)*2)
	ContextI := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(i)))
	proofTvk, err := zkpeqlog.NewProof(ctx, ContextI, round.EC(), pointG, round.temp.childAddr,
		round.temp.Rjs[i], tvkShare, ri, common.RejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	shareList = append(shareList, tvkShare)
	proofList = append(proofList, proofTvk)

	for k, pointU := range round.temp.pointUs {
		// for b
		bShare := pointU.ScalarMult(ri)
		if bShare == nil {
			return round.WrapError(errors.New("error in computing bShare"), round.PartyID())
		}
		round.temp.Bs[k] = bShare
		bProof, err := zkpeqlog.NewProof(ctx, ContextI, round.EC(), pointG, pointU,
			round.temp.Rjs[i], bShare, ri, common.RejectionSample)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		shareList = append(shareList, bShare)
		proofList = append(proofList, bProof)

		// for gamma
		gammaShare := pointU.ScalarMult(round.temp.w1i)
		if gammaShare == nil {
			return round.WrapError(errors.New("error in computing gammaShare"), round.PartyID())
		}
		round.temp.gammas[k] = gammaShare
		gammaProof, err := zkpeqlog.NewProof(ctx, ContextI, round.EC(), pointG, pointU,
			round.temp.bigW1s[i], gammaShare, round.temp.w1i, common.RejectionSample)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		shareList = append(shareList, gammaShare)
		proofList = append(proofList, gammaProof)
	}

	round.temp.ri = ri
	round.temp.R = R
	// broadcast ri to other parties
	r3msg := NewSignRound3Message(round.PartyID(), shareList, proofList)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
