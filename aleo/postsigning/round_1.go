// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postsigning

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/aleo/keygen"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"go.opentelemetry.io/otel/trace"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *RequestData) tss.Round {
	return &round1{
		&base{params, key, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1, false}}
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
	fmt.Printf("%s, %s \n", hex.EncodeToString(ssid), hex.EncodeToString(round.temp.ssid))
	if !bytes.Equal(ssid, round.temp.ssid) {
		return round.WrapError(errors.New("ssid not match"), round.PartyID())
	}

	modN := common.ModInt(round.EC().Params().N)

	responseShare := modN.Sub(round.temp.ri, modN.Mul(round.temp.challenge, round.temp.wi))
	round.temp.zi = responseShare

	r1msg := NewPSignRound1Message(round.PartyID(), responseShare)
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.psignRound1Messages {
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
	if _, ok := msg.Content().(*PSignRound1Message); ok {
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
	if round.temp.PkSigDerivationDelta.Cmp(zero) != 0 {
		x1i = modN.Add(x1i, round.temp.PkSigDerivationDelta)
		pkDelta := crypto.ScalarBaseMult(round.EC(), round.temp.PkSigDerivationDelta)
		for j := range pkShares {
			point, err := pkShares[j].Add(pkDelta)
			if err != nil {
				return err
			}
			pkShares[j] = point
		}
	}

	w1i, bigW1s := crypto.PrepareForSigning(round.Params().EC(), i, len(ks), x1i, ks, pkShares)

	round.temp.wi = w1i
	round.temp.bigWs = bigW1s
	return nil
}
