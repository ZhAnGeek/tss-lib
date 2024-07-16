// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package decryption

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
)

func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, kj []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
	modQ := common.ModInt(ec.Params().N)
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
		// big.Int Div is calculated as: a/b = a * modInv(b,q) // coef = \Pi ks[j]/(ks[j]-ks[i])
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ks[j], ks[i])))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := kj[j]
		ksj := ks[j]

		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			if ksj.Cmp(ksc) == 0 {
				panic(fmt.Errorf("index of two parties are equal"))
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}
	return
}
