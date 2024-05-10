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

func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint, pubkey, bigR *crypto.ECPoint) (wi *big.Int) {
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
	ksi := ks[i]

	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
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

	return
}