// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmod_test

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/common"
	. "github.com/binance-chain/tss-lib/crypto/zkp/mod"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

var (
	Session = []byte("session")
)

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	p, q, N := preParams.P, preParams.Q, preParams.NTildei
	// p2, q2 := new(big.Int).Mul(p, big.NewInt(2)), new(big.Int).Mul(q, big.NewInt(2))
	p2, q2 := new(big.Int).Lsh(p, 1), new(big.Int).Lsh(q, 1)
	P, Q := new(big.Int).Add(p2, big.NewInt(1)), new(big.Int).Add(q2, big.NewInt(1))

	proof, err := NewProof(Session, N, P, Q)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}

// NewProofForged from TOB-BIN-7
func NewProofForged(Session []byte, N, P, Q *big.Int) (*ProofMod, error) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// set quadratic non residue to 0
	W := zero
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N}, Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}
	modN := common.ModInt(N)
	NINV := new(big.Int).ModInverse(N, Phi)
	X := [Iterations]*big.Int{}
	var Bbz []byte
	Bbz = append(Bbz, byte(255))
	Z := [Iterations]*big.Int{}
	for i := range Y {
		// set Zi as usual
		Zi := modN.Exp(Y[i], NINV)
		// set Xi as 0
		X[i], Z[i] = zero, Zi
		// set bi as 1 to guarantee that Xi is multiplied
		Bbz = append(Bbz, byte(1))
	}
	A := new(big.Int).SetBytes(Bbz)
	B := new(big.Int).SetBytes(Bbz)
	return &ProofMod{W: W, X: X, A: A, B: B, Z: Z}, nil
}

func genPrime() *big.Int {
	q := new(big.Int)
	qBitLen := 1024
	four := big.NewInt(4)
	one := big.NewInt(1)
	bytes := make([]byte, (qBitLen+7)/8)
	for {
		_, err := io.ReadFull(rand.Reader, bytes)
		if err != nil {
			panic("could not sample")
		}
		q.SetBytes(bytes)
		// random prime % 4 == 1 (not blum)
		if q.ProbablyPrime(20) && new(big.Int).Mod(q, four).Cmp(one) == 0 {
			return q
		}
	}
	return nil
}

func TestForged(test *testing.T) {
	P := genPrime()
	Q := genPrime()
	N := new(big.Int).Mul(P, Q)
	proof, err := NewProofForged(Session, N, P, Q)
	assert.NoError(test, err)
	ok := proof.Verify(Session, N)
	assert.False(test, ok, "proof must verify")
}
