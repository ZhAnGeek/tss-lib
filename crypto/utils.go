// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
)

var (
	HmacSize = 32
	zero     = new(big.Int).SetInt64(0)
	one      = new(big.Int).SetInt64(1)
)

func GenerateNTildei(safePrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if safePrimes[0] == nil || safePrimes[1] == nil {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %v", safePrimes)
	}
	if !safePrimes[0].ProbablyPrime(30) || !safePrimes[1].ProbablyPrime(30) {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: expected two primes")
	}
	NTildei = new(big.Int).Mul(safePrimes[0], safePrimes[1])
	h1 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}

func BLSEncryptByECPoint(suite []byte, pubKey *ECPoint, message []byte) ([]byte, error) {
	var totalPK = make([]byte, 0)
	if bytes.Equal(suite, bls12381.GetBLSSignatureSuiteG1()) {
		totalPK = make([]byte, 192)
		pubKey.X().FillBytes(totalPK[:96])
		pubKey.Y().FillBytes(totalPK[96:])
	}
	if bytes.Equal(suite, bls12381.GetBLSSignatureSuiteG2()) {
		totalPK = make([]byte, 96)
		pubKey.X().FillBytes(totalPK[:48])
		pubKey.Y().FillBytes(totalPK[48:])
	}
	return bls12381.Encrypt(suite, totalPK, message)
}

func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*ECPoint) (wi *big.Int, bigWs []*ECPoint) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(bigXs) {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs)))
	}
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	// batch inverse ks[j] - ks[i]
	Ksji := make([]*big.Int, pax*pax)
	for j := 0; j < pax; j++ {
		for i := 0; i < pax; i++ {
			if j == i {
				continue
			}
			Ksji[i+j*pax] = new(big.Int).Sub(ks[j], ks[i])
		}
	}
	invKsji, _ := common.BatchInvert(Ksji, ec.Params().N)
	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		err := common.CheckBigIntNotNil(invKsji[i+j*pax])
		if err != nil {
			panic(err.Error())
		}
		coef := modQ.Mul(ks[j], invKsji[i+j*pax])
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			err := common.CheckBigIntNotNil(invKsji[j+c*pax])
			if err != nil {
				panic(err.Error())
			}
			Q := modQ.Mul(ks[c], invKsji[j+c*pax])
			bigWj = bigWj.ScalarMult(Q)
		}
		bigWs[j] = bigWj
	}
	return
}
