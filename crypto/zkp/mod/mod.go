// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmod

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
)

const (
	Iterations         = 13
	ProofModBytesParts = Iterations*2 + 3
)

var (
	one = big.NewInt(1)
)

type (
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)

// isQuandraticResidue checks Euler criterion
func isQuandraticResidue(X, N *big.Int) bool {
	modN := common.ModInt(N)
	XEXP := modN.Exp(X, new(big.Int).Rsh(N, 1))
	ok := XEXP.Cmp(big.NewInt(1)) == 0
	return ok
}

func NewProof(Session []byte, N, P, Q *big.Int) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuandraticNonResidue(N)

	// Fig 16.2
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16.3
	modN, modPhi := common.ModInt(N), common.ModInt(Phi)
	NINV := new(big.Int).ModInverse(N, Phi)
	X := [Iterations]*big.Int{}
	var Abz, Bbz []byte
	Abz = append(Abz, byte(255)) // add sentinel to ensuring the len(A.Bytes()) == Iterations+1
	Bbz = append(Bbz, byte(255))
	Z := [Iterations]*big.Int{}

	for i := range Y {
		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}
			if isQuandraticResidue(Yi, P) && isQuandraticResidue(Yi, Q) {
				e := new(big.Int).Add(Phi, big.NewInt(4))
				e = new(big.Int).Rsh(e, 3)
				e = modPhi.Mul(e, e)
				Xi := modN.Exp(Yi, e)
				Zi := modN.Exp(Y[i], NINV)
				X[i], Z[i] = Xi, Zi
				Abz = append(Abz, byte(a))
				Bbz = append(Bbz, byte(b))
			}
		}
	}
	A := new(big.Int).SetBytes(Abz)
	B := new(big.Int).SetBytes(Bbz)

	return &ProofMod{W: W, X: [Iterations]*big.Int(X), A: A, B: B, Z: Z}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{pf.W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}

	// Fig 16. Verification
	{
		if N.Bit(0) == 0 || N.ProbablyPrime(16) {
			return false
		}
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
			}
			chs <- true
		}(i)

		go func(i int) {
			a := int(pf.A.Bytes()[i+1]) // sentinel at 0
			b := int(pf.B.Bytes()[i+1])
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			return false
		}
	}

	return true
}

func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		bzs[1+i] = pf.X[i].Bytes()
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		bzs[Iterations+3+i] = pf.Z[i].Bytes()
	}
	return bzs
}
