// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpeqlog

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
)

const (
	ProofEqLogBytesParts = 2
)

type (
	ProofEqLog struct {
		C, R *big.Int
	}
)

// NewProof implements proofenc
func NewProof(ctx context.Context, Session []byte, ec elliptic.Curve, g, h, x, y *crypto.ECPoint, k *big.Int) (*ProofEqLog, error) {
	if ec == nil || g == nil || h == nil || x == nil || y == nil {
		return nil, errors.New("ProfEqLog constructor received nil value(s)")
	}
	if !tss.SameCurve(ec, g.Curve()) || !tss.SameCurve(ec, h.Curve()) || !tss.SameCurve(ec, x.Curve()) || !tss.SameCurve(ec, y.Curve()) {
		return nil, errors.New("ProofEqLog constructor received ec not match")
	}
	// IsOnCurve also returns false if point is infinity point
	if !g.IsOnCurve() || !h.IsOnCurve() || !x.IsOnCurve() || !y.IsOnCurve() {
		return nil, errors.New("ProofEqLog constructor received point not on curve or identity point")
	}
	if !g.IsInSubGroup() || !h.IsInSubGroup() || !x.IsInSubGroup() || !y.IsInSubGroup() {
		return nil, errors.New("ProofEqLog constructor received point not in correct subgroup")
	}

	q := ec.Params().N
	r := common.GetRandomPositiveInt(q)
	cmt1 := g.ScalarMult(r)
	if cmt1 == nil || cmt1.IsInfinityPoint() {
		return nil, errors.New("ProofEqLog constructor compute r*G should not fail")
	}
	cmt2 := h.ScalarMult(r)
	if cmt2 == nil || cmt2.IsInfinityPoint() {
		return nil, errors.New("ProofEqLog constructor compute r*H should not fail")
	}

	var ch *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, g.X(), g.Y(), h.X(), h.Y(), x.X(), x.Y(),
			cmt1.X(), cmt1.Y(), cmt2.X(), cmt2.Y())
		ch = common.RejectionSample(q, eHash)
	}

	// Fig 14.3
	modN := common.ModInt(ec.Params().N)
	res := modN.Mul(ch, k)
	res = modN.Add(res, r)

	return &ProofEqLog{C: ch, R: res}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofEqLog, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofEqLogBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofEqLog", ProofEqLogBytesParts)
	}
	return &ProofEqLog{
		C: new(big.Int).SetBytes(bzs[0]),
		R: new(big.Int).SetBytes(bzs[1]),
	}, nil
}

func (pf *ProofEqLog) Verify(ctx context.Context, Session []byte, ec elliptic.Curve, g, h, x, y *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || g == nil || h == nil || x == nil || y == nil {
		return false
	}
	if !tss.SameCurve(ec, g.Curve()) || !tss.SameCurve(ec, h.Curve()) || !tss.SameCurve(ec, x.Curve()) || !tss.SameCurve(ec, y.Curve()) {
		return false
	}
	// IsOnCurve also returns false if point is infinity point
	if !g.IsOnCurve() || !h.IsOnCurve() || !x.IsOnCurve() || !y.IsOnCurve() {
		return false
	}
	if !g.IsInSubGroup() || !h.IsInSubGroup() || !x.IsInSubGroup() || !y.IsInSubGroup() {
		return false
	}

	q := ec.Params().N
	if !common.IsInInterval(pf.C, ec.Params().N) {
		return false
	}
	if !common.IsInInterval(pf.R, ec.Params().N) {
		return false
	}

	rG := g.ScalarMult(pf.R)
	cX := x.ScalarMult(pf.C)
	cmt1, err := rG.Sub(cX)
	if err != nil {
		return false
	}
	rH := h.ScalarMult(pf.R)
	cY := y.ScalarMult(pf.C)
	cmt2, err := rH.Sub(cY)
	if err != nil {
		return false
	}
	var ch *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, g.X(), g.Y(), h.X(), h.Y(), x.X(), x.Y(),
			cmt1.X(), cmt1.Y(), cmt2.X(), cmt2.Y())
		ch = common.RejectionSample(q, eHash)
	}
	if ch.Cmp(pf.C) != 0 {
		return false
	}

	return true
}

func (pf *ProofEqLog) ValidateBasic() bool {
	return pf.C != nil &&
		pf.R != nil
}

func (pf *ProofEqLog) Bytes() [ProofEqLogBytesParts][]byte {
	return [...][]byte{
		pf.C.Bytes(),
		pf.R.Bytes(),
	}
}
