// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto/bls12381"
)

var (
	HmacSize = 32
	zero = new(big.Int).SetInt64(0)
	one  = new(big.Int).SetInt64(1)
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

func EncryptByECPoint(suite []byte, pubKey *ECPoint, message []byte) ([]byte, error) {
	var totalPK = make([]byte, 0)
	if bytes.Compare(suite, bls12381.GetBLSSignatureSuiteG1()) == 0 {
		totalPK = make([]byte, 192)
		pubKey.X().FillBytes(totalPK[:96])
		pubKey.Y().FillBytes(totalPK[96:])
	}
	if bytes.Compare(suite, bls12381.GetBLSSignatureSuiteG2()) == 0 {
		totalPK = make([]byte, 96)
		pubKey.X().FillBytes(totalPK[:48])
		pubKey.Y().FillBytes(totalPK[48:])
	}
	message = bls12381.PadToLengthBytesInPlacePKCSS7(message, aes.BlockSize)
	encryptedMessage := make([]byte, aes.BlockSize+bls12381.PointG2Size+bls12381.PointG1Size+bls12381.Sha256SumSize+len(message)+HmacSize)
	err := bls12381.EncryptByGeneratedAes(suite, encryptedMessage, totalPK, message)
	return encryptedMessage, err
}
