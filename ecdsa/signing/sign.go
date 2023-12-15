// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"context"
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

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, predata *presigning.PreSignatureData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData, dump chan<- *LocalDumpPB) tss.Round {
	return &sign1{&base{params, key, predata, data, temp, out, end, dump, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *sign1) Start(ctx context.Context) *tss.Error {
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
	Pi := round.PartyID()
	round.ok[i] = true

	if round.temp.m.BitLen() > round.EC().Params().N.BitLen() {
		return round.WrapError(errors.New("e=Hash(m) is mal formatted"))
	}

	if tss.SameCurve(round.EC(), tss.StarkCurve()) && round.temp.m.Cmp(starkcurve.Stark().EcdsaMax) >= 0 {
		return round.WrapError(errors.New("e=Hash(m) is mal formatted for the stark curve, you only could sign less than order msg"))
	}

	round.temp.SsidNonce = round.predata.UnmarshalSsidNonce()
	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	predataSsid := round.predata.UnmarshalSsid()
	if !bytes.Equal(ssid, predataSsid) {
		return round.WrapError(errors.New("preSig ssid not match"), Pi)
	}

	round.temp.ssid = ssid
	round.temp.KShare = round.predata.UnmarshalKShare()
	round.temp.ChiShare = round.predata.UnmarshalChiShare()
	bigR, err := round.predata.UnmarshalBigR(round.EC())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.BigR = bigR

	// Fig 8. Round 1. compute signature share
	modN := common.ModInt(round.EC().Params().N)
	Rx := round.temp.BigR.X()
	Ry := round.temp.BigR.Y()
	SigmaShare := modN.Add(modN.Mul(round.temp.KShare, round.temp.m), modN.Mul(Rx, round.temp.ChiShare))
	SigmaShareDelta := modN.Mul(Rx, modN.Mul(round.temp.KShare, round.temp.KeyDerivationDelta))
	SigmaShare = modN.Add(SigmaShare, SigmaShareDelta)
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	RxBytes := common.PadToLengthBytesInPlace(Rx.Bytes(), bitSizeInBytes)

	r1msg := NewSignRound1Message(round.PartyID(), SigmaShare, RxBytes, Ry)
	round.out <- r1msg

	round.temp.SigmaShare = SigmaShare

	return nil
}

func (round *sign1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.R4msgSigmaShare {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *sign1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *sign1) NextRound() tss.Round {
	round.started = false
	return &signout{round}
}

func (round *sign1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	BigXs := round.key.BigXj

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, BigWs := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

	round.temp.w = wi
	round.temp.BigWs = BigWs
	return nil
}
