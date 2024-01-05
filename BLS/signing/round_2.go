// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/tracer"
	"github.com/Safulet/tss-lib-private/tss"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/trace"
)

var (
	zero = big.NewInt(0)
)

func (round *round2) Start(ctx context.Context) *tss.Error {
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

	i := round.PartyID().Index
	round.ok[i] = true

	for j, msg := range round.temp.signRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*SignRound1Message)
		round.temp.sig[j] = r1msg.UnmarshalSignature()

		PKj := make([]byte, round.temp.PublicKeySize*2)
		round.temp.BigWs[j].X().FillBytes(PKj[:round.temp.PublicKeySize])
		round.temp.BigWs[j].Y().FillBytes(PKj[round.temp.PublicKeySize:])

		if ok := bls12381.Verify(round.temp.suite, PKj, round.temp.m, round.temp.sig[j].Bytes()); !ok {
			return round.WrapError(errors.New("Partial message failed to verify"), round.Parties().IDs()[j])
		}
	}

	totalSign, err := AddOnSignature(round.temp.suite, round.temp.sig)

	if err != nil {
		fmt.Println("signature fail to construct")
	}

	PubKey := round.key.PubKey
	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		point, err := round.key.PubKey.Add(round.temp.pkDelta)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		PubKey = point
	}

	totalPK := make([]byte, round.temp.PublicKeySize*2)
	PubKey.X().FillBytes(totalPK[:round.temp.PublicKeySize])
	PubKey.Y().FillBytes(totalPK[round.temp.PublicKeySize:])

	if !bls12381.Verify(round.temp.suite, totalPK, round.temp.m, totalSign.Bytes()) {
		return round.WrapError(errors.New("fail to verify total signature"))
	}

	round.data.M = round.temp.m
	round.data.Signature = totalSign.Bytes()
	round.isFinished = true
	round.end <- round.data

	return nil
}

func AddOnSignature(suite []byte, sign []*big.Int) (*big.Int, error) {
	if bytes.Compare(suite, bls12381.GetBLSSignatureSuiteG1()) == 0 {
		return AddOnSignatureG1(sign)
	}
	return AddOnSignatureG2(sign)
}

func AddOnSignatureG1(sign []*big.Int) (*big.Int, error) {
	g1 := bls.NewG1()
	res := g1.Zero()
	for _, s := range sign {
		tmp, err := bls12381.PadToLengthBytesInPlace(s.Bytes(), bls12381.SignatureSizeG1*2)
		if err != nil {
			return nil, err
		}
		addPoint, err := g1.FromBytes(tmp)
		if err != nil {
			return nil, err
		}
		g1.Add(res, res, addPoint)
	}
	return new(big.Int).SetBytes(g1.ToBytes(res)), nil
}

func AddOnSignatureG2(sign []*big.Int) (*big.Int, error) {
	g2 := bls.NewG2()
	res := g2.Zero()
	for _, s := range sign {
		tmp, err := bls12381.PadToLengthBytesInPlace(s.Bytes(), bls12381.SignatureSizeG2*2)
		if err != nil {
			return nil, err
		}
		addPoint, err := g2.FromBytes(tmp)
		if err != nil {
			return nil, err
		}
		g2.Add(res, res, addPoint)
	}
	return new(big.Int).SetBytes(g2.ToBytes(res)), nil
}
