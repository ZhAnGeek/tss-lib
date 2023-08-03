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
		return nil, errors.New("ProveEqLog constructor received nil value(s)")
	}
	if !tss.SameCurve(ec, g.Curve()) || !tss.SameCurve(ec, h.Curve()) || !tss.SameCurve(ec, x.Curve()) || !tss.SameCurve(ec, y.Curve()) {
		return nil, errors.New("ProofEqLog constructor received ec not match")
	}
	if tss.SameCurve(ec, tss.Edwards()) || tss.SameCurve(ec, tss.Curve25519()) {
		g1 := g.EightInvEight()
		if !g1.Equals(g) {
			return nil, errors.New("uncleared cofactor")
		}
		h1 := h.EightInvEight()
		if !h1.Equals(h) {
			return nil, errors.New("uncleared cofactor")
		}
		x1 := x.EightInvEight()
		if !x1.Equals(x) {
			return nil, errors.New("uncleared cofactor")
		}
		y1 := y.EightInvEight()
		if !y1.Equals(y) {
			return nil, errors.New("uncleared cofactor")
		}
	}

	q := ec.Params().N
	r := common.GetRandomPositiveInt(q)
	cmt1 := g.ScalarMult(r)
	if cmt1 == nil {
		return nil, errors.New("ProofEqLog constructor compute r*G should not fail")
	}
	cmt2 := h.ScalarMult(r)
	if cmt2 == nil {
		return nil, errors.New("ProofEqLog constructor compute r*H should not fail")
	}

	var ch *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, g.X(), g.Y(), h.X(), h.Y(), x.X(), x.Y(),
			cmt1.X(), cmt1.Y(), cmt2.X(), cmt2.Y())
		ch = common.RejectionSample(q, eHash)
	}

	// Fig 14.3
	res := new(big.Int).Mul(ch, k)
	res = new(big.Int).Add(res, r)

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

func pointSub(Lhs, Rhs *crypto.ECPoint) (*crypto.ECPoint, error) {
	if tss.SameCurve(Rhs.Curve(), tss.S256()) || tss.SameCurve(Rhs.Curve(), tss.P256()) ||
		tss.SameCurve(Rhs.Curve(), tss.Curve25519()) {
		Rn, err := crypto.NewECPoint(Rhs.Curve(), Rhs.X(), new(big.Int).Sub(Rhs.Curve().Params().P, Rhs.Y()))
		if err != nil {
			return nil, err
		}
		ret, err := Lhs.Add(Rn)
		if err != nil {
			return nil, err
		}
		return ret, nil
	}
	if tss.SameCurve(Rhs.Curve(), tss.Edwards()) {
		Rn, err := crypto.NewECPoint(Rhs.Curve(), new(big.Int).Sub(Rhs.Curve().Params().P, Rhs.X()), Rhs.Y())
		if err != nil {
			return nil, err
		}
		ret, err := Lhs.Add(Rn)
		if err != nil {
			return nil, err
		}
		return ret, nil
	}
	// Todo serialization problem in curve
	Rn := Rhs.ScalarMult(new(big.Int).Sub(Rhs.Curve().Params().N, big.NewInt(1)))
	ret, err := Lhs.Add(Rn)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (pf *ProofEqLog) Verify(ctx context.Context, Session []byte, ec elliptic.Curve, g, h, x, y *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || g == nil || h == nil || x == nil || y == nil {
		return false
	}
	if !tss.SameCurve(ec, g.Curve()) || !tss.SameCurve(ec, h.Curve()) || !tss.SameCurve(ec, x.Curve()) || !tss.SameCurve(ec, y.Curve()) {
		fmt.Println("check 1")
		return false
	}
	q := ec.Params().N
	if tss.SameCurve(ec, tss.Edwards()) || tss.SameCurve(ec, tss.Curve25519()) {
		g1 := g.EightInvEight()
		if !g1.Equals(g) {
			fmt.Println("check 2")
			return false
		}
		h1 := h.EightInvEight()
		if !h1.Equals(h) {
			fmt.Println("check 3")
			return false
		}
		x1 := x.EightInvEight()
		if !x1.Equals(x) {
			fmt.Println("check 4")
			return false
		}
		y1 := y.EightInvEight()
		if !y1.Equals(y) {
			fmt.Println("check 5")
			return false
		}
	}

	rG := g.ScalarMult(pf.R)
	cX := x.ScalarMult(pf.C)
	cmt1, err := pointSub(rG, cX)
	if err != nil {
		fmt.Println("check 6")
		return false
	}
	rH := h.ScalarMult(pf.R)
	cY := y.ScalarMult(pf.C)
	cmt2, err := pointSub(rH, cY)
	if err != nil {
		fmt.Println("check 7")
		return false
	}
	var ch *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, g.X(), g.Y(), h.X(), h.Y(), x.X(), x.Y(),
			cmt1.X(), cmt1.Y(), cmt2.X(), cmt2.Y())
		ch = common.RejectionSample(q, eHash)
	}
	if ch.Cmp(pf.C) != 0 {
		fmt.Println("check 8")
		return false
	}

	fmt.Println("check 9; ok")
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
