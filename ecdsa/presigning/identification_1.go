// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning

import (
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	zkpaffg "github.com/Safulet/tss-lib-private/crypto/zkp/affg"
	zkpdec "github.com/Safulet/tss-lib-private/crypto/zkp/dec"
	zkpmul "github.com/Safulet/tss-lib-private/crypto/zkp/mul"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"
	"go.opentelemetry.io/otel/trace"
)

func newRound5(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *PreSignatureData, dump chan<- *LocalDumpPB) tss.Round {
	return &identification5{&presign4{&presign3{&presign2{&presign1{
		&base{params, key, temp, out, end, dump, make([]bool, len(params.Parties().IDs())), false, 5, false}}}}}}
}

func (round *identification5) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Pi := round.PartyID()
	round.ok[i] = true
	ContextI := append(round.temp.Ssid, big.NewInt(int64(i)).Bytes()...)
	rejectionSample := tss.GetRejectionSampleFunc(round.Params().Version())

	// Fig 7. Output.2
	// Broadcast part
	H, rho, err := round.key.PaillierSK.HomoMultObfuscate(round.temp.KShare, round.temp.G)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	proofMul, err := zkpmul.NewProof(ctx, ContextI, round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K,
		round.temp.G, H, round.temp.KShare, rho, round.temp.KNonce, rejectionSample)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// Fill to prevent nil
	round.temp.DeltaMtADs[i] = big.NewInt(1)
	round.temp.DeltaMtAFs[i] = big.NewInt(1)

	msg1 := NewIdentificationRound1Message1(Pi, H, proofMul, round.temp.DeltaMtADs, round.temp.DeltaMtAFs)
	round.out <- msg1

	// P2P part
	proofAffgs := make([][]*zkpaffg.ProofAffg, round.PartyCount())
	for i := range proofAffgs {
		proofAffgs[i] = make([]*zkpaffg.ProofAffg, round.PartyCount())
	}
	// send to k
	for k := range round.Parties().IDs() {
		if k == i {
			continue
		}
		// process Dji
		for j := range round.Parties().IDs() {
			if j == i {
				continue
			}
			if k == j {
				// already computed
				proofAffgs[k][j] = round.temp.DeltaMtADProofs[j]
				continue
			}
			pkj := round.key.PaillierPKs[j]
			pki := &round.key.PaillierSK.PublicKey
			NCap := round.key.NTildej[k]
			s := round.key.H1j[k]
			t := round.key.H2j[k]
			Kj := round.temp.R1msgK[j]
			Dji := round.temp.DeltaMtADs[j]
			Fji := round.temp.DeltaMtAFs[j]
			BigGammai := round.temp.BigGammaShare
			gammai := round.temp.GammaShare
			betaNeg := round.temp.DeltaMtABetaNeg[j]
			sij := round.temp.DeltaMtASij[j]
			rij := round.temp.DeltaMtARij[j]

			proof, err := zkpaffg.NewProof(ctx, ContextI, round.EC(), pkj, pki, NCap, s, t,
				Kj, Dji, Fji, BigGammai, gammai, betaNeg, sij, rij, rejectionSample)
			if err != nil {
				return round.WrapError(err, Pi)
			}
			proofAffgs[k][j] = proof

		}
	}
	// Calc DeltaShare2 s.t. Enc(DeltaShare2) = DeltaShareEnc
	DeltaShare2 := new(big.Int).Mul(round.temp.KShare, round.temp.GammaShare)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		DeltaShare2 = new(big.Int).Add(DeltaShare2, round.temp.DeltaShareAlphas[j])
		DeltaShare2 = new(big.Int).Add(DeltaShare2, round.temp.DeltaShareBetas[j])
	}
	DeltaShareEnc := H
	modN2 := common.ModInt(round.key.PaillierSK.NSquare())
	q := round.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q3, q)
	Q3Enc, err := round.key.PaillierSK.EncryptWithRandomness(q3, new(big.Int).SetBytes(round.temp.Ssid))
	if err != nil {
		return round.WrapError(err, Pi)
	}
	for k := range round.Parties().IDs() {
		if k == i {
			continue
		}
		var err error
		DeltaShareEnc, err = round.key.PaillierSK.HomoAdd(DeltaShareEnc, round.temp.R2msgDeltaD[k])
		if err != nil {
			return round.WrapError(err, Pi)
		}
		FinvEnc := modN2.ModInverse(round.temp.DeltaMtAFs[k])
		err = common.CheckBigIntNotNil(FinvEnc)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		BetaEnc := modN2.Mul(Q3Enc, FinvEnc)
		DeltaShareEnc, err = round.key.PaillierSK.HomoAdd(DeltaShareEnc, BetaEnc)
		if err != nil {
			return round.WrapError(err, Pi)
		}
	}
	nonce, err := round.key.PaillierSK.GetRandomness(DeltaShareEnc)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	proofDecs := make([]*zkpdec.ProofDec, round.PartyCount())
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}

		ContextJ := append(round.temp.Ssid, big.NewInt(int64(j)).Bytes()...)
		proof, err := zkpdec.NewProof(ctx, ContextJ, round.EC(), &round.key.PaillierSK.PublicKey, DeltaShareEnc, round.temp.DeltaShare, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], DeltaShare2, nonce, rejectionSample)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		proofDecs[j] = proof

	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg2 := NewIdentificationRound1Message2(Pj, Pi, proofAffgs[j], proofDecs[j])
		round.out <- msg2
	}

	return nil
}

func (round *identification5) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.R5msgH {
		if round.ok[j] {
			continue
		}
		if msg == nil || round.temp.R5msgH[j] == nil || round.temp.R5msgProofMul[j] == nil ||
			round.temp.R5msgDjis[j] == nil || round.temp.R5msgFjis[j] == nil ||
			round.temp.R5msgProofAffg[j] == nil || round.temp.R5msgProofDec[j] == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *identification5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*IdentificationRound1Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*IdentificationRound1Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *identification5) NextRound() tss.Round {
	round.started = false
	return &identification6{round}
}
