// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keyshare_affine_transform

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"go.opentelemetry.io/otel/trace"
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *keygen.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, key, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
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

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	modN := common.ModInt(round.EC().Params().N)
	b := modN.Mul(round.temp.B, modN.ModInverse(big.NewInt(int64(round.Parties().IDs().Len()))))
	ui := modN.Add(modN.Mul(round.temp.W, round.temp.A), b)

	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	alphai, Ai := zkpsch.NewAlpha(round.EC())

	ridBz, err := common.GetRandomBytes(SafeBitsLen)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	rid := new(big.Int).SetBytes(ridBz)

	listToHash, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmtRandomnessBz, err := common.GetRandomBytes(SafeBitsLen)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmtRandomness := new(big.Int).SetBytes(cmtRandomnessBz)
	listToHash = append(listToHash, Ai.X(), Ai.Y(), rid, cmtRandomness)
	VHash := common.SHA512_256i(ctx, listToHash...)
	{
		msg := NewKTRound1Message(round.PartyID(), VHash)
		round.out <- msg
	}

	round.save.LocalPreParams = round.key.LocalPreParams
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	round.temp.alphai = alphai
	round.temp.Ai = Ai
	round.temp.cmtRandomness = cmtRandomness
	round.temp.rid = rid
	round.temp.vs = vs
	round.temp.ui = ui
	round.temp.shares = shares

	round.save.NTildej = round.key.NTildej
	round.save.H1j, round.save.H2j = round.key.H1j, round.key.H2j
	round.save.PaillierPKs = round.key.PaillierPKs

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KTRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.r1msgVHashs {
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

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

func (round *round1) prepare() error {
	i := round.PartyID().Index

	modN := common.ModInt(round.EC().Params().N)
	xi := modN.Add(round.key.Xi, round.temp.KeyDerivationDelta)
	ks := round.key.Ks
	BigXs := round.key.BigXj
	gDelta := crypto.ScalarBaseMult(round.EC(), round.temp.KeyDerivationDelta)
	var err error
	for idx := range BigXs {
		BigXs[idx], err = BigXs[idx].Add(gDelta)
		if err != nil {
			return err
		}
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, BigWs := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, BigXs)

	round.temp.W = wi
	round.temp.BigWs = BigWs

	return nil
}
