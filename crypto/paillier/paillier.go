// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// The Paillier Crypto-system is an additive crypto-system. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plain texts.
// Additionally, Paillier Crypto-system supports further computations:
//
// * Encrypted integers can be added together
// * Encrypted integers can be multiplied by an unencrypted integer
// * Encrypted integers and unencrypted integers can be added together
//
// Implementation adheres to GG18Spec (6)

package paillier

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/Safulet/tss-lib-private/common"
)

const (
	ProofIters         = 13
	pQBitLenDifference = 3 // >1020-bit P-Q
)

type (
	PublicKey struct {
		N  *big.Int
		NS *big.Int
		Ga *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN, // lcm(p-1, q-1)
		PhiN *big.Int // (p-1) * (q-1)
		LgInv *big.Int // cache
	}

	// Proof uses the new GenerateXs method in GG18Spec (6)
	Proof [ProofIters]*big.Int
)

var (
	ErrMessageTooLong   = fmt.Errorf("the message is too large or < 0")
	ErrMessageMalFormed = fmt.Errorf("the message is mal-formed")
	ErrWrongRandomness  = fmt.Errorf("the randomness is invalid")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPair(modulusBitLen int, timeout time.Duration, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}

	// KS-BTL-F-03: use two safe primes for P, Q
	var P, Q, N *big.Int
	{
		tmp := new(big.Int)
		for {
			sgps, err := common.GetRandomSafePrimesConcurrent(modulusBitLen/2, 2, timeout, concurrency)
			if err != nil {
				return nil, nil, err
			}
			P, Q = sgps[0].SafePrime(), sgps[1].SafePrime()
			// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
			if tmp.Sub(P, Q).BitLen() >= (modulusBitLen/2)-pQBitLenDifference {
				break
			}
		}
		N = tmp.Mul(P, Q)
	}

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}

// ----- //

func (publicKey *PublicKey) EncryptAndReturnRandomness(m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m == nil || m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageMalFormed
	}
	x = common.GetRandomPositiveRelativelyPrimeInt(publicKey.N)
	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := common.IntCalc().Exp(publicKey.Gamma(), m, N2)
	// 2. x^N mod N2
	xN := common.IntCalc().Exp(x, publicKey.N, N2)
	// 3. (1) * (2) mod N2
	c = common.ModInt(N2).Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) Encrypt(m *big.Int) (c *big.Int, err error) {
	c, _, err = publicKey.EncryptAndReturnRandomness(m)
	return
}

func (publicKey *PublicKey) EncryptWithRandomness(m, x *big.Int) (c *big.Int, err error) {
	if m == nil || m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageMalFormed
	}
	if x == nil || x.Cmp(publicKey.N) == 1 || x.Cmp(zero) == -1 {
		return nil, ErrWrongRandomness
	}
	if !common.IsNumberInMultiplicativeGroup(publicKey.N, x) {
		return nil, ErrWrongRandomness
	}

	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := common.IntCalc().Exp(publicKey.Gamma(), m, N2)
	// 2. x^N mod N2
	xN := common.IntCalc().Exp(x, publicKey.N, N2)
	// 3. (1) * (2) mod N2
	c = common.ModInt(N2).Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
	if m == nil || m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageMalFormed
	}
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	return common.ModInt(N2).Exp(c1, m), nil
}

func (publicKey *PublicKey) HomoMultObfuscate(m, c1 *big.Int) (*big.Int, *big.Int, error) {
	if m == nil || m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageMalFormed
	}
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	c2 := common.ModInt(N2).Exp(c1, m)
	x := common.GetRandomPositiveRelativelyPrimeInt(publicKey.N)
	xN := common.IntCalc().Exp(x, publicKey.N, N2)
	c2 = common.ModInt(N2).Mul(c2, xN)
	return c2, x, nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	N2 := publicKey.NSquare()
	if c1 == nil || c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageMalFormed
	}
	if c2 == nil || c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { // c2 < 0 || c2 >= N2 ?
		return nil, ErrMessageMalFormed
	}
	// c1 * c2 mod N2
	return common.ModInt(N2).Mul(c1, c2), nil
}

func (publicKey *PublicKey) NSquare() *big.Int {
	if publicKey.NS == nil {
		publicKey.NS = new(big.Int).Mul(publicKey.N, publicKey.N)
	}
	return publicKey.NS
}

// AsInts returns the PublicKey serialised to a slice of *big.Int for hashing
func (publicKey *PublicKey) AsInts() []*big.Int {
	return []*big.Int{publicKey.N, publicKey.Gamma()}
}

// Gamma returns N+1
func (publicKey *PublicKey) Gamma() *big.Int {
	if publicKey.Ga == nil {
		publicKey.Ga = new(big.Int).Add(publicKey.N, one)
	}
	return publicKey.Ga
}

// ----- //

func (privateKey *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	N2 := privateKey.NSquare()
	if c == nil || c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // c < 0 || c >= N2 ?
		return nil, ErrMessageMalFormed
	}
	cg := new(big.Int).GCD(nil, nil, c, N2)
	if cg.Cmp(one) == 1 {
		return nil, ErrMessageMalFormed
	}
	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(common.IntCalc().Exp(c, privateKey.LambdaN, N2), privateKey.N)
	if privateKey.LgInv == nil {
		// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
		Lg := L(common.IntCalc().Exp(privateKey.Gamma(), privateKey.LambdaN, N2), privateKey.N)
		// 3. (1) * modInv(2) mod N
		inv := new(big.Int).ModInverse(Lg, privateKey.N)
		m = common.ModInt(privateKey.N).Mul(Lc, inv)
	} else {
		m = common.ModInt(privateKey.N).Mul(Lc, privateKey.LgInv)
	}
	return
}

func (privateKey *PrivateKey) CacheLgInv() bool {
	N2 := privateKey.NSquare()
	if privateKey.LgInv == nil {
		// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
		Lg := L(common.IntCalc().Exp(privateKey.Gamma(), privateKey.LambdaN, N2), privateKey.N)
		// 3. (1) * modInv(2) mod N
		inv := new(big.Int).ModInverse(Lg, privateKey.N)
		privateKey.LgInv = inv // TODO
		return true
	}
	return false
}

func (privateKey *PrivateKey) GetRandomness(c *big.Int) (r *big.Int, err error) {
	N2 := privateKey.NSquare()
	m, err := privateKey.Decrypt(c)
	if err != nil {
		return nil, err
	}
	modN2 := common.ModInt(N2)
	c0 := modN2.Mul(m, privateKey.N)
	c0 = modN2.Sub(one, c0)
	c0 = modN2.Mul(c, c0)

	modPhiN := common.ModInt(privateKey.PhiN)
	niv := modPhiN.ModInverse(privateKey.N)
	err = common.CheckBigIntNotNil(niv)
	if err != nil {
		return nil, err
	}

	modN := common.ModInt(privateKey.N)
	r = modN.Exp(c0, niv)
	return
}

// ----- utils

func L(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, one)
	return new(big.Int).Div(t, N)
}
