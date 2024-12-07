// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon4"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/commitments"
	"github.com/Safulet/tss-lib-private/v2/crypto/hash2curve"
	zkpeqlog "github.com/Safulet/tss-lib-private/v2/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

const (
	PathFormat  = "TSS-LIB#DeriveKey#EC#%s#SCHEME#%s#CHAINCODE#%s#PATH#%s"
	SkTagScheme = "ALEO_SKTAG"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *RequestOut) tss.Round {
	return &round1{
		&base{params, key, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
}

func getPathString(ec elliptic.Curve, scheme string, pChainCode, path []byte) (string, error) {
	ecName, ok := tss.GetCurveName(ec)
	if !ok {
		return "", errors.New("error get curve name")
	}
	var fullPath = fmt.Sprintf(PathFormat,
		ecName, scheme, string(pChainCode), string(path))
	return fullPath, nil
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round1")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round1")

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.ssid = ssid

	// 1. select di, ei
	di := common.GetRandomPositiveInt(round.EC().Params().N)
	ei := common.GetRandomPositiveInt(round.EC().Params().N)

	// 2. make commitment
	pointDi := crypto.ScalarBaseMult(round.Params().EC(), di)
	pointEi := crypto.ScalarBaseMult(round.Params().EC(), ei)
	cmt := commitments.NewHashCommitment(ctx, pointDi.X(), pointDi.Y(), pointEi.X(), pointEi.Y())

	// 3. store r1 message pieces
	round.temp.di = di
	round.temp.ei = ei
	round.temp.pointDi = pointDi
	round.temp.pointEi = pointEi
	round.temp.deCommit = cmt.D

	// compute V1, proofV1
	ContextI := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(i)))
	wPath1, err := getPathString(round.EC(), SkTagScheme, round.temp.ssid, big.NewInt(1).Bytes())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wPath2, err := getPathString(round.EC(), SkTagScheme, round.temp.ssid, big.NewInt(2).Bytes())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wP1 := new(big.Int).SetBytes(common.SHA512_256(ctx, []byte(wPath1))[:31])
	wP2 := new(big.Int).SetBytes(common.SHA512_256(ctx, []byte(wPath2))[:31])
	pointH1, err := poseidon4.HashToGroup([]*big.Int{wP1, wP2}, hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	pointV1 := pointH1.ScalarMult(round.temp.w1i)
	pointG := crypto.ScalarBaseMult(round.EC(), common.One)
	proof1, err := zkpeqlog.NewProof(ctx, ContextI, round.EC(), pointG, pointH1, round.temp.bigW1s[i], pointV1, round.temp.w1i, common.RejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wPath1, err = getPathString(round.EC(), SkTagScheme, round.temp.ssid, big.NewInt(101).Bytes())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wPath2, err = getPathString(round.EC(), SkTagScheme, round.temp.ssid, big.NewInt(102).Bytes())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wP1 = new(big.Int).SetBytes(common.SHA512_256(ctx, []byte(wPath1))[:31])
	wP2 = new(big.Int).SetBytes(common.SHA512_256(ctx, []byte(wPath2))[:31])
	pointH2, err := poseidon4.HashToGroup([]*big.Int{wP1, wP2}, hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	pointV2 := pointH2.ScalarMult(round.temp.w2i)
	proof2, err := zkpeqlog.NewProof(ctx, ContextI, round.EC(), pointG, pointH2, round.temp.bigW2s[i], pointV2, round.temp.w2i, common.RejectionSample)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.pointH1 = pointH1
	round.temp.pointH2 = pointH2
	round.temp.pointV1 = pointV1
	round.temp.pointV2 = pointV2

	// 4. broadcast commitment
	r1msg2 := NewSignRound1Message(round.PartyID(), cmt.C, pointV1, proof1, pointV2, proof2)
	round.temp.signRound1Messages[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index
	ks := round.key.Ks
	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}

	modN := common.ModInt(round.EC().Params().N)
	x1i := round.key.SkSigShare
	pkShares := make([]*crypto.ECPoint, len(round.key.PkSigShares))
	copy(pkShares, round.key.PkSigShares)
	pkSigShift := crypto.ScalarBaseMult(round.EC(), round.temp.PkSigDelta)
	if round.temp.PkSigDelta.Cmp(zero) != 0 {
		x1i = modN.Add(x1i, round.temp.PkSigDelta)
		for j := range pkShares {
			point, err := pkShares[j].Add(pkSigShift)
			if err != nil {
				return err
			}
			pkShares[j] = point
		}
	}
	PkSig, err := round.key.PkSig.Add(pkSigShift)
	if err != nil {
		return err
	}
	round.temp.childPkSig = PkSig

	w1i, bigW1s := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), x1i, ks, pkShares)

	x2i := round.key.RSigShare
	prShares := make([]*crypto.ECPoint, len(round.key.PrSigShares))
	copy(prShares, round.key.PrSigShares)
	prSigShift := crypto.ScalarBaseMult(round.EC(), round.temp.PrSigDelta)
	if round.temp.PkSigDelta.Cmp(zero) != 0 {
		x2i = modN.Add(x2i, round.temp.PrSigDelta)
		for j := range prShares {
			point, err := prShares[j].Add(prSigShift)
			if err != nil {
				return err
			}
			prShares[j] = point
		}
	}
	PrSig, err := round.key.PrSig.Add(prSigShift)
	if err != nil {
		return err
	}
	round.temp.childPrSig = PrSig
	SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{PkSig.X(), PrSig.X()})
	PkPrf := crypto.ScalarBaseMult(round.EC(), SkPrf)
	Address, err := PkSig.Add(PrSig)
	if err != nil {
		return err
	}
	Address, err = PkPrf.Add(Address)
	if err != nil {
		return err
	}
	round.temp.childAddr = Address

	w2i, bigW2s := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), x2i, ks, prShares)

	round.temp.w1i = w1i
	round.temp.bigW1s = bigW1s
	round.temp.w2i = w2i
	round.temp.bigW2s = bigW2s
	return nil
}
