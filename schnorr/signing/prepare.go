// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
)

// PrepareForSigning runs before signing, when the set of parties to be signed is determined.
// Each party locally convert his (t, n) share x_i into an additive share w_i such that x = \sum_{j \in S} w_j
// In addition, using the values X_j that were output from the key generation protocol,
// the players can locally compute for all j \in S, W_j = g^{w_j}.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
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

	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		modQTemp := modQ.ModInverse(new(big.Int).Sub(ksj, ksi))
		err := common.CheckBigIntNotNil(modQTemp)
		if err != nil {
			panic(err.Error())
		}
		coef := modQ.Mul(ksj, modQTemp)
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				panic(fmt.Errorf("index of two parties are equal"))
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			modQTemp := modQ.ModInverse(new(big.Int).Sub(ksc, ksj))
			err := common.CheckBigIntNotNil(modQTemp)
			if err != nil {
				panic(err.Error())
			}
			val := modQ.Mul(ksc, modQTemp)
			bigWj = bigWj.ScalarMult(val)
		}
		bigWs[j] = bigWj
	}
	return
}
