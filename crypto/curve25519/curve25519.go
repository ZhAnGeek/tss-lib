// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package curve25519

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

//  referred from https://sagecell.sagemath.org/?q=czvfze
var (
	positiveSqrtRoot, _ = new(big.Int).SetString("6853475219497561581579357271197624642482790079785650197046958215289687604742", 10)
	one                 = new(big.Int).SetInt64(1)
	zero                = new(big.Int).SetInt64(0)
	two                 = new(big.Int).SetInt64(2)
	three               = new(big.Int).SetInt64(3)
	A                   = new(big.Int).SetInt64(486662)
)

type Curve25519 struct {
	*elliptic.CurveParams
	twisted *edwards.TwistedEdwardsCurve
}

func (curve *Curve25519) IsOnCurve(x, y *big.Int) bool {
	if x.Cmp(one) == 0 && y.Cmp(zero) == 0 {
		return false
	}
	xt, yt := curve.ConvertPointFromMontgomery(x, y)
	return curve.twisted.IsOnCurve(xt, yt)
}

// Add ec arithmetic equations https://en.wikipedia.org/wiki/Montgomery_curve#Addition
// also from http://hyperelliptic.org/EFD/g1p/auto-montgom.html
func (curve *Curve25519) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if x1.Cmp(one) == 0 && y1.Cmp(zero) == 0 {
		return x2, y2
	}
	if x2.Cmp(one) == 0 && y2.Cmp(zero) == 0 {
		return x1, y1
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) != 0 {
		return one, zero
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return curve.Double(x1, y1)
	}

	modP := common.ModInt(curve.Params().P)
	t1s := new(big.Int).Sub(y2, y1)
	t1 := modP.Mul(t1s, t1s)
	t2s := new(big.Int).Sub(x2, x1)
	t2 := modP.Mul(t2s, t2s)
	x3 := modP.Sub(modP.Mul(t1, new(big.Int).ModInverse(t2, curve.Params().P)), modP.Add(A, modP.Add(x1, x2)))

	t1 = modP.Add(modP.Mul(two, x1), modP.Add(A, x2))
	t2 = modP.Sub(y2, y1)
	t3 := modP.Sub(x2, x1)
	t4 := modP.Mul(modP.Mul(t1, new(big.Int).Sub(y2, y1)), new(big.Int).ModInverse(modP.Sub(x2, x1), curve.Params().P))
	t5 := modP.Mul(modP.Mul(modP.Mul(t2, t2), t2), new(big.Int).ModInverse(modP.Mul(modP.Mul(t3, t3), t3), curve.Params().P))

	y3 := modP.Sub(modP.Sub(t4, t5), y1)
	return x3, y3
}

// Double ec arithmetic equations https://en.wikipedia.org/wiki/Montgomery_curve#Doubling
func (curve *Curve25519) Double(x1, y1 *big.Int) (x, y *big.Int) {
	if x1.Cmp(one) == 0 && y1.Cmp(zero) == 0 {
		return one, zero
	}
	if x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0 {
		return one, zero
	}
	modP := common.ModInt(curve.Params().P)
	x12 := new(big.Int).Mul(x1, x1)
	y12 := new(big.Int).Mul(y1, y1)
	x12m3 := new(big.Int).Mul(three, x12)
	am2x1 := new(big.Int).Mul(new(big.Int).Mul(two, A), x1)
	y12m4 := new(big.Int).Mul(new(big.Int).SetInt64(4), y12)
	y13m8 := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).SetInt64(8), y12), y1)

	x12m3am2x1 := new(big.Int).Add(new(big.Int).Add(x12m3, am2x1), one)
	x12m3am2x12 := new(big.Int).Mul(x12m3am2x1, x12m3am2x1)
	x12m3am2x13 := new(big.Int).Mul(x12m3am2x12, x12m3am2x1)
	t2x1 := new(big.Int).Add(x1, x1)
	t3x1 := new(big.Int).Add(t2x1, x1)
	x2 := modP.Sub(modP.Sub(x12m3am2x12.Mul(x12m3am2x12, new(big.Int).ModInverse(y12m4, curve.Params().P)), A), t2x1)

	y2 := modP.Sub(modP.Sub(modP.Mul(modP.Mul(modP.Add(t3x1, A), x12m3am2x1), new(big.Int).ModInverse(new(big.Int).Add(y1, y1), curve.Params().P)),
		modP.Mul(x12m3am2x13, new(big.Int).ModInverse(y13m8, curve.Params().P))), y1)

	return x2, y2
}

func (curve *Curve25519) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	tx, ty := one, zero
	tmp1, tmp2 := zero, zero

	bits := fmt.Sprintf("%b", new(big.Int).SetBytes(k))
	for _, bit := range bits {
		tx, ty = curve.Double(tx, ty)
		tmp1, tmp2 = curve.Add(tx, ty, x1, y1)
		if bit == '1' {
			tx, ty = tmp1, tmp2
		} else {
			tmp1, tmp2 = tx, ty
		}
	}
	return tx, ty
}

func (curve *Curve25519) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, k)
}

func (curve *Curve25519) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve *Curve25519) ConvertPointFromMontgomery(x1, y1 *big.Int) (x, y *big.Int) {
	one := new(big.Int).SetInt64(1)
	zero := new(big.Int).SetInt64(0)

	// map (0, 0) to (0, -1)
	if x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0 {
		return zero, new(big.Int).SetInt64(-1)
	}

	// map point of infinity (1, 0) to (0, 1)
	if x1.Cmp(one) == 0 && y1.Cmp(zero) == 0 {
		return zero, one
	}
	modP := common.ModInt(curve.twisted.Params().P)
	addx := new(big.Int).Add(x1, one)
	subx := new(big.Int).Sub(x1, one)
	x = modP.Mul(positiveSqrtRoot, modP.Mul(x1, modP.ModInverse(y1)))
	y = modP.Mul(subx, modP.ModInverse(addx))
	return x, y
}

// C25519 base point referred https://safecurves.cr.yp.to/base.html
func C25519() *Curve25519 {
	c := new(Curve25519)
	c.twisted = edwards.Edwards()
	params := c.twisted.Params()
	params.Gx = new(big.Int).SetInt64(9)
	params.Gy, _ = new(big.Int).SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
	c.CurveParams = params
	return c
}
