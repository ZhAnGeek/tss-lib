// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmul

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
)

const (
	ProofMulBytesParts = 5
)

type (
	ProofMul struct {
		A, B, Z, U, V *big.Int
	}
)

var (
	one = big.NewInt(1)
)

// NewProof implements proofmul
func NewProof(ctx context.Context, Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, X, Y, C, x, rho, rhox *big.Int, rejectionSample common.RejectionSampleFunc) (*ProofMul, error) {
	if pk == nil || X == nil || Y == nil || C == nil || rho == nil || rhox == nil {
		return nil, errors.New("ProveMul constructor received nil value(s)")
	}
	q := ec.Params().N

	// Fig 28.1 sample
	alpha := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	r := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	s := common.GetRandomPositiveRelativelyPrimeInt(pk.N)

	modNSquared := common.ModInt(pk.NSquare())
	A := modNSquared.Exp(Y, alpha)
	A = modNSquared.Mul(A, modNSquared.Exp(r, pk.N))

	B := modNSquared.Exp(pk.Gamma(), alpha)
	B = modNSquared.Mul(B, modNSquared.Exp(s, pk.N))

	// Fig 28.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, append(pk.AsInts(), X, Y, C, A, B)...)
		e = rejectionSample(q, eHash)
	}

	// Fig 14.3
	z := new(big.Int).Mul(e, x)
	z = new(big.Int).Add(z, alpha)

	modN := common.ModInt(pk.N)
	u := modN.Exp(rho, e)
	u = modN.Mul(u, r)

	v := modN.Exp(rhox, e)
	v = modN.Mul(v, s)

	return &ProofMul{A: A, B: B, Z: z, U: u, V: v}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMul, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofMulBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMul", ProofMulBytesParts)
	}
	return &ProofMul{
		A: new(big.Int).SetBytes(bzs[0]),
		B: new(big.Int).SetBytes(bzs[1]),
		Z: new(big.Int).SetBytes(bzs[2]),
		U: new(big.Int).SetBytes(bzs[3]),
		V: new(big.Int).SetBytes(bzs[4]),
	}, nil
}

func (pf *ProofMul) Verify(ctx context.Context, Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, X, Y, C *big.Int, rejectionSample common.RejectionSampleFunc) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || X == nil || Y == nil || C == nil {
		return false
	}

	q := ec.Params().N

	if pf.A.Sign() == -1 || !common.IsInInterval(pf.A, pk.NSquare()) {
		return false
	}
	if pf.B.Sign() == -1 || !common.IsInInterval(pf.B, pk.NSquare()) {
		return false
	}

	if pf.U.Sign() == -1 || !common.IsInInterval(pf.U, pk.N) {
		return false
	}

	if pf.V.Sign() == -1 || !common.IsInInterval(pf.V, pk.N) {
		return false
	}
	if pf.Z.Sign() != 1 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.A, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.B, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.U, pk.N).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.V, pk.N).Cmp(one) != 0 {
		return false
	}

	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(ctx, Session, append(pk.AsInts(), X, Y, C, pf.A, pf.B)...)
		e = rejectionSample(q, eHash)
	}

	// Fig 14. Equality Check
	modNSquare := common.ModInt(pk.NSquare())
	{
		YEXPz := modNSquare.Exp(Y, pf.Z)
		uEXPN := modNSquare.Exp(pf.U, pk.N)
		left := modNSquare.Mul(YEXPz, uEXPN)

		CEXPe := modNSquare.Exp(C, e)
		right := modNSquare.Mul(pf.A, CEXPe)

		if left.Cmp(right) != 0 {
			return false
		}
	}

	{
		Np1EXPz := modNSquare.Exp(pk.Gamma(), pf.Z)
		CEXPN := modNSquare.Exp(pf.V, pk.N)
		left := modNSquare.Mul(Np1EXPz, CEXPN)

		XEXPe := modNSquare.Exp(X, e)
		right := modNSquare.Mul(pf.B, XEXPe)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

func (pf *ProofMul) ValidateBasic() bool {
	return pf.A != nil &&
		pf.B != nil &&
		pf.Z != nil &&
		pf.U != nil &&
		pf.V != nil
}

func (pf *ProofMul) Bytes() [ProofMulBytesParts][]byte {
	return [...][]byte{
		pf.A.Bytes(),
		pf.B.Bytes(),
		pf.Z.Bytes(),
		pf.U.Bytes(),
		pf.V.Bytes(),
	}
}
