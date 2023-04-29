// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package curve25519

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurve25519BasePoint(t *testing.T) {

	curve25519 := C25519()
	x, y := curve25519.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())

	assert.Equal(t, x.String(), "9")
	assert.Equal(t, y.String(), "14781619447589544791020593568409986887264606134616475288964881837755586237401")

	xt, yt := curve25519.ConvertPointFromMontgomery(x, y)
	assert.Equal(t, xt.String(), "42783823269122696939284341094755422415180979639778424813682678720006717057747")
	assert.Equal(t, yt.String(), "46316835694926478169428394003475163141307993866256225615783033603165251855960")

	x2m, y2m := curve25519.Add(x, y, x, y) // montgomery
	x2m2, y2m2 := curve25519.Double(x, y)
	assert.Equal(t, x2m.String(), x2m2.String())
	assert.Equal(t, y2m.String(), y2m2.String())
}

func TestCurve25519Double(t *testing.T) {

	curve25519 := C25519()
	x, y := curve25519.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())

	assert.Equal(t, x.String(), "9")
	assert.Equal(t, y.String(), "14781619447589544791020593568409986887264606134616475288964881837755586237401")

	xm2, ym2 := curve25519.Double(x, y)
	assert.Equal(t, "14847277145635483483963372537557091634710985132825781088887140890597596352251", xm2.String())
	assert.Equal(t, "8914613091229147831277935472048643066880067899251840418855181793938505594211", ym2.String())

	xm3, ym3 := curve25519.Add(x, y, xm2, ym2)
	assert.Equal(t, "12697861248284385512127539163427099897745340918349830473877503196793995869202", xm3.String())
	assert.Equal(t, "18782504731206017997790968374142055202547214238579664877619644464800823583275", ym3.String())

	xm3byMul, ym3byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(3).Bytes())
	assert.Equal(t, xm3.String(), xm3byMul.String())
	assert.Equal(t, ym3.String(), ym3byMul.String())

	xm16byMul, ym16byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(16).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm16byMul, ym16byMul), true)
	assert.Equal(t, "22944042183821758196639555843847020275590080432146737615610504920265089949526", xm16byMul.String())
	assert.Equal(t, "1451359425793293828576886974342397680559034521703210423152945409819843894135", ym16byMul.String())

	xm100byMul, ym100byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(100).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm100byMul, ym100byMul), true)
	assert.Equal(t, "44032819295671302737126221960004779200206561247519912509082330344845040669336", xm100byMul.String())
	assert.Equal(t, "49270038226210525340151214444327294350884211061153958845837287101994892076605", ym100byMul.String())
}

func TestCurve25519Add(t *testing.T) {

	curve25519 := C25519()
	x, y := curve25519.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())

	assert.Equal(t, x.String(), "9")
	assert.Equal(t, y.String(), "14781619447589544791020593568409986887264606134616475288964881837755586237401")

	xm2, ym2 := curve25519.Double(x, y)
	assert.Equal(t, "14847277145635483483963372537557091634710985132825781088887140890597596352251", xm2.String())
	assert.Equal(t, "8914613091229147831277935472048643066880067899251840418855181793938505594211", ym2.String())

	xm3, ym3 := curve25519.Add(x, y, xm2, ym2)
	assert.Equal(t, "12697861248284385512127539163427099897745340918349830473877503196793995869202", xm3.String())
	assert.Equal(t, "18782504731206017997790968374142055202547214238579664877619644464800823583275", ym3.String())

	xm3byMul, ym3byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(3).Bytes())
	assert.Equal(t, xm3.String(), xm3byMul.String())
	assert.Equal(t, ym3.String(), ym3byMul.String())

	xm16byMul, ym16byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(16).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm16byMul, ym16byMul), true)
	assert.Equal(t, "22944042183821758196639555843847020275590080432146737615610504920265089949526", xm16byMul.String())
	assert.Equal(t, "1451359425793293828576886974342397680559034521703210423152945409819843894135", ym16byMul.String())

	xm100byMul, ym100byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(100).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm100byMul, ym100byMul), true)
	assert.Equal(t, "44032819295671302737126221960004779200206561247519912509082330344845040669336", xm100byMul.String())
	assert.Equal(t, "49270038226210525340151214444327294350884211061153958845837287101994892076605", ym100byMul.String())
}

func TestCurve25519ScalarMult(t *testing.T) {

	curve25519 := C25519()
	x, y := curve25519.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())

	assert.Equal(t, x.String(), "9")
	assert.Equal(t, y.String(), "14781619447589544791020593568409986887264606134616475288964881837755586237401")

	xm2, ym2 := curve25519.Double(x, y)
	assert.Equal(t, "14847277145635483483963372537557091634710985132825781088887140890597596352251", xm2.String())
	assert.Equal(t, "8914613091229147831277935472048643066880067899251840418855181793938505594211", ym2.String())

	xm3, ym3 := curve25519.Add(x, y, xm2, ym2)
	assert.Equal(t, "12697861248284385512127539163427099897745340918349830473877503196793995869202", xm3.String())
	assert.Equal(t, "18782504731206017997790968374142055202547214238579664877619644464800823583275", ym3.String())

	xm3byMul, ym3byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(3).Bytes())
	assert.Equal(t, xm3.String(), xm3byMul.String())
	assert.Equal(t, ym3.String(), ym3byMul.String())

	xm16byMul, ym16byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(16).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm16byMul, ym16byMul), true)
	assert.Equal(t, "22944042183821758196639555843847020275590080432146737615610504920265089949526", xm16byMul.String())
	assert.Equal(t, "1451359425793293828576886974342397680559034521703210423152945409819843894135", ym16byMul.String())

	xm100byMul, ym100byMul := curve25519.ScalarBaseMult(new(big.Int).SetInt64(100).Bytes())
	assert.Equal(t, curve25519.IsOnCurve(xm100byMul, ym100byMul), true)
	assert.Equal(t, "44032819295671302737126221960004779200206561247519912509082330344845040669336", xm100byMul.String())
	assert.Equal(t, "49270038226210525340151214444327294350884211061153958845837287101994892076605", ym100byMul.String())
}
