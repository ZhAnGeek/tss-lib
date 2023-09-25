// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	zkpdec "github.com/Safulet/tss-lib-private/crypto/zkp/dec"
	zkpmulstar "github.com/Safulet/tss-lib-private/crypto/zkp/mulstar"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/ecdsa/presigning"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"
	"go.opentelemetry.io/otel/trace"
)

func newRound3(params *tss.Parameters, key *keygen.LocalPartySaveData, predata *presigning.PreSignatureData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData, dump chan<- *LocalDumpPB) tss.Round {
	return &identification1{&signout{&sign1{
		&base{params, key, predata, data, temp, out, end, dump, make([]bool, len(params.Parties().IDs())), false, 3}}}}
}

func (round *identification1) Start(ctx context.Context) *tss.Error {
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
	Pi := round.PartyID()
	round.ok[i] = true
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// Fig 8. Output.
	H, rho, err := round.key.PaillierSK.HomoMultObfuscate(round.temp.w, round.temp.K)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	proofH, err := zkpmulstar.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, g, round.temp.BigWs[i], round.temp.K, H, round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.w, rho, rejectionSample)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// Calc ChiShare2 s.t. Enc(ChiShare2)
	ChiShare2 := new(big.Int).Mul(round.temp.KShare, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ChiShare2 = new(big.Int).Add(ChiShare2, round.temp.ChiShareAlphas[j])
		ChiShare2 = new(big.Int).Add(ChiShare2, round.temp.ChiShareBetas[j])
	}
	SigmaShare2 := new(big.Int).Add(new(big.Int).Mul(round.temp.KShare, round.temp.m), new(big.Int).Mul(round.temp.BigR.X(), ChiShare2))

	ChiShareEnc := H
	modN2 := common.ModInt(round.key.PaillierSK.NSquare())
	q := round.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q3, q)
	Q3Enc, err := round.key.PaillierSK.EncryptWithRandomness(q3, new(big.Int).SetBytes(round.temp.ssid))
	if err != nil {
		return round.WrapError(err, Pi)
	}
	for k := range round.Parties().IDs() {
		if k == i {
			continue
		}
		var err error
		ChiShareEnc, err = round.key.PaillierSK.HomoAdd(ChiShareEnc, round.temp.R2msgChiD[k])
		if err != nil {
			return round.WrapError(err, Pi)
		}
		FinvEnc := modN2.ModInverse(round.temp.ChiMtAFs[k])
		err = common.CheckBigIntNotNil(FinvEnc)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		BetaEnc := modN2.Mul(Q3Enc, FinvEnc)
		ChiShareEnc, err = round.key.PaillierSK.HomoAdd(ChiShareEnc, BetaEnc)
		if err != nil {
			return round.WrapError(err, Pi)
		}
	}
	SigmaShareEnc, err := round.key.PaillierSK.HomoMult(round.temp.m, round.temp.K)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	part, err := round.key.PaillierSK.HomoMult(round.temp.BigR.X(), ChiShareEnc)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	SigmaShareEnc, err = round.key.PaillierSK.HomoAdd(SigmaShareEnc, part)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	nonce, err := round.key.PaillierSK.GetRandomness(SigmaShareEnc)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	round.temp.ChiMtADs[i] = round.temp.ChiMtADs[1-i]
	round.temp.ChiMtAFs[i] = round.temp.ChiMtAFs[1-i]
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		rejectionSample := tss.GetRejectionSampleFunc(round.Params().Version())
		proofDec, err := zkpdec.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, SigmaShareEnc, round.temp.SigmaShare, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], SigmaShare2, nonce, rejectionSample)
		if err != nil {
			return round.WrapError(err, Pi)
		}

		r6msg := NewIdentificationRound1Message(Pj, round.PartyID(), H, proofH, round.temp.ChiMtADs, round.temp.ChiMtAFs, proofDec, Q3Enc)
		round.out <- r6msg
	}

	return nil
}

func (round *identification1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.R5msgH {
		if round.ok[j] {
			continue
		}
		if msg == nil || round.temp.R5msgDjis[j] == nil || round.temp.R5msgFjis[j] == nil ||
			round.temp.R5msgProofDec[j] == nil || round.temp.R5msgProofMulstar[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *identification1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*IdentificationRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *identification1) NextRound() tss.Round {
	round.started = false
	return &identification2{round}
}