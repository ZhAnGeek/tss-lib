// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/tss"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
)

const (
	ProofSchBytesParts = 3
)

type (
	ProofSch struct {
		A *crypto.ECPoint
		Z *big.Int
	}
)

// NewProof implements proofsch
func NewProof(ctx context.Context, Session []byte, X *crypto.ECPoint, x *big.Int, rejectionSample common.RejectionSampleFunc) (*ProofSch, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy) // already on the curve.

	// Fig 22.1
	alpha := common.GetRandomPositiveInt(q)
	A := crypto.ScalarBaseMult(ec, alpha)

	// Fig 22.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, ec.Params().B, ec.Params().N, ec.Params().P,
			X.X(), X.Y(), g.X(), g.Y(), A.X(), A.Y())
		e = rejectionSample(q, eHash)
	}

	// Fig 22.3
	z := new(big.Int).Mul(e, x)
	z = common.ModInt(q).Add(alpha, z)

	return &ProofSch{A: A, Z: z}, nil
}

// New First message
func NewAlpha(ec elliptic.Curve) (*big.Int, *crypto.ECPoint) {
	q := ec.Params().N

	// Fig 22.1
	alpha := common.GetRandomPositiveInt(q)
	A := crypto.ScalarBaseMult(ec, alpha)

	return alpha, A
}

// NewProof implements proofsch
func NewProofWithAlpha(ctx context.Context, Session []byte, X, A *crypto.ECPoint, alpha, x *big.Int, rejectionSample common.RejectionSampleFunc) (*ProofSch, error) {
	if x == nil || X == nil || !X.ValidateBasic() || A == nil || !A.ValidateBasic() || alpha == nil {
		return nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy) // already on the curve.

	// Fig 22.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, ec.Params().B, ec.Params().N, ec.Params().P,
			X.X(), X.Y(), g.X(), g.Y(), A.X(), A.Y())
		e = rejectionSample(q, eHash)
	}

	// Fig 22.3
	z := new(big.Int).Mul(e, x)
	z = common.ModInt(q).Add(alpha, z)

	return &ProofSch{A: A, Z: z}, nil
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofSch, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofSchBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofSch", ProofSchBytesParts)
	}

	var x, y, z *big.Int
	if ecName, ok := tss.GetCurveName(ec); ok {
		if ecName == tss.BLS12381G2 || ecName == tss.BLS12381G1 {
			x = new(big.Int).SetBytes(bzs[0])
			y = new(big.Int).SetBytes(bzs[1])
			z = new(big.Int).SetBytes(bzs[2])
		} else {
			x = new(big.Int).Mod(new(big.Int).SetBytes(bzs[0]), ec.Params().P)
			y = new(big.Int).Mod(new(big.Int).SetBytes(bzs[1]), ec.Params().P)
			z = new(big.Int).Mod(new(big.Int).SetBytes(bzs[2]), ec.Params().N)
		}

	} else {
		return nil, errors.New("ec not supported")
	}

	point, err := crypto.NewECPoint(ec, x, y)
	if err != nil {
		return nil, err
	}
	return &ProofSch{
		A: point,
		Z: z,
	}, nil
}

func (pf *ProofSch) Verify(ctx context.Context, Session []byte, X *crypto.ECPoint, rejectionSample common.RejectionSampleFunc) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil || !X.ValidateBasic() {
		return false
	}
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)

	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, ec.Params().B, ec.Params().N, ec.Params().P,
			X.X(), X.Y(), g.X(), g.Y(), pf.A.X(), pf.A.Y())
		e = rejectionSample(q, eHash)
	}

	// Fig 22. Verification
	left := crypto.ScalarBaseMult(ec, pf.Z)
	XEXPe := X.ScalarMult(e)
	right, err := pf.A.Add(XEXPe)
	if err != nil {
		return false
	}
	return left.Equals(right)
}

func (pf *ProofSch) ValidateBasic() bool {
	return pf.Z != nil && pf.A != nil
}

func (pf *ProofSch) Bytes() [ProofSchBytesParts][]byte {
	return [...][]byte{
		pf.A.X().Bytes(),
		pf.A.Y().Bytes(),
		pf.Z.Bytes(),
	}
}
