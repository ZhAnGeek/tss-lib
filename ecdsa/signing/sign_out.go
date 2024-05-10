// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/starkcurve"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/ecdsa/presigning"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	"go.opentelemetry.io/otel/trace"
)

func VerifySig(ec elliptic.Curve, R *crypto.ECPoint, S *big.Int, m *big.Int, PK *crypto.ECPoint) bool {
	// stark curve will drop r, sinv exceed 2**251
	if tss.SameCurve(ec, tss.StarkCurve()) {
		valid, _ := starkcurve.Stark().Verify(m, R.X(), S, PK.X(), PK.Y())
		return valid
	}

	modN := common.ModInt(ec.Params().N)
	SInv := modN.ModInverse(S)
	err := common.CheckBigIntNotNil(SInv)
	if err != nil {
		return false
	}
	mG := crypto.ScalarBaseMult(ec, m)
	rx := R.X()
	rxPK := PK.ScalarMult(rx)
	R2, err := mG.Add(rxPK)
	if err != nil {
		return false
	}
	R2 = R2.ScalarMult(SInv)
	return R2.Equals(R)
}

func newRound2(params *tss.Parameters, key *keygen.LocalPartySaveData, predata *presigning.PreSignatureData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData, dump chan<- *LocalDumpPB) tss.Round {
	return &sign2{&sign1{
		&base{params, key, predata, data, temp, out, end, dump, make([]bool, len(params.Parties().IDs())), false, 2, false}}}
}

func (round *sign2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round2")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round2")

	round.number = 2
	round.started = true
	round.resetOK()

	// Fig 8. Output. combine signature shares verify and output
	Sigma := round.temp.SigmaShare
	modN := common.ModInt(round.Params().EC().Params().N)
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		Sigma = modN.Add(Sigma, round.temp.R4msgSigmaShare[j])
	}
	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.BigR.X().Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	if round.temp.BigR.Y().Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if Sigma.Cmp(halfN) > 0 {
		Sigma.Sub(round.Params().EC().Params().N, Sigma)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := (round.Params().EC().Params().BitSize + 7) / 8
	round.data.R = common.PadToLengthBytesInPlace(round.temp.BigR.X().Bytes(), bitSizeInBytes)
	round.data.S = common.PadToLengthBytesInPlace(Sigma.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	round.data.M = round.temp.m.Bytes()

	PKDelta := round.key.ECDSAPub
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		gDelta := crypto.ScalarBaseMult(round.EC(), round.temp.KeyDerivationDelta)
		var err error
		PKDelta, err = PKDelta.Add(gDelta)
		if err != nil {
			return round.WrapError(errors.New("PubKey derivation failed"), round.PartyID())
		}
	}

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     PKDelta.X(), // round.key.ECDSAPub.X(),
		Y:     PKDelta.Y(), // round.key.ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), round.temp.BigR.X(), Sigma) || VerifySig(round.Params().EC(), round.temp.BigR, Sigma, round.temp.m, PKDelta)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	round.isFinished = true
	round.end <- round.data

	if round.NeedsIdentifaction() && round.dump != nil {
		du := &LocalDump{
			Temp:     round.temp,
			RoundNum: round.number + 1, // Notice, dierct restore into identification 1
			Index:    round.PartyID().Index,
		}
		duPB := NewLocalDumpPB(du.Index, du.RoundNum, du.Temp)
		round.dump <- duPB
	}

	return nil
}

func (round *sign2) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *sign2) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *sign2) NextRound() tss.Round {
	return nil // finished!
}
