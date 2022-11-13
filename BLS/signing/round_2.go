// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"fmt"
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/pkg/errors"

	"github.com/Safulet/tss-lib-private/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/tss"
)

var (
	ErrNumSharesBelowThreshold = fmt.Errorf("not enough shares to satisfy the threshold")
	zero                       = big.NewInt(0)
)

func (round *round2) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

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
	}

	totalSign, err := AddOnSignature(round.temp.sig)

	if err != nil {
		fmt.Println("signature fail to construct")
	}

	totalPK := make([]byte, 192)
	round.key.PubKey.X().FillBytes(totalPK[:96])
	round.key.PubKey.Y().FillBytes(totalPK[96:])

	if round.temp.KeyDerivationDelta.Cmp(zero) != 0 {
		g2 := bls.NewG2()
		totalPKPoint, err := g2.FromBytes(totalPK)
		if err != nil {
			return round.WrapError(err)
		}
		bytes := bls12381.PadToLengthBytesInPlace(round.temp.derivePubKey.Bytes(), 192)
		tmpPoint, err := g2.FromBytes(bytes)
		if err != nil {
			return round.WrapError(err)
		}
		g2.MulScalar(tmpPoint, tmpPoint, big.NewInt(int64(round.Threshold()+1)))
		g2.Add(totalPKPoint, totalPKPoint, tmpPoint)
		totalPK = g2.ToBytes(totalPKPoint)
	}

	if !bls12381.Verify(totalPK, round.temp.m, totalSign.Bytes()) {
		return round.WrapError(errors.New("fail to verify total signature"))
	}

	round.data.M = round.temp.m
	round.data.Signature = totalSign.Bytes()
	round.end <- *round.data

	return nil
}

func AddOnSignature(sign []*big.Int) (*big.Int, error) {
	g1 := bls.NewG1()
	res := g1.Zero()
	for _, s := range sign {
		tmp := bls12381.PadToLengthBytesInPlace(s.Bytes(), 96)
		addPoint, _ := g1.FromBytes(tmp)
		g1.Add(res, res, addPoint)
	}
	return new(big.Int).SetBytes(g1.ToBytes(res)), nil
}
