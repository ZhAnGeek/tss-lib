// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package poseidon4

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/crypto/hash2curve"
	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	v1, ok := new(big.Int).SetString("2747380058067926024392396834194632562725011784276175733372764264674145639690", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("4669766862083161671500363968195935072348039486297434174954457851807822454654", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2)

	h := HashToScalarPSD4([]*big.Int{v1, v2})
	fmt.Println("hash:", h)
	expected, ok := new(big.Int).SetString("518600152633288345588125542642570631760180689299457649171985855814755300910", 10)
	assert.True(t, ok)
	assert.Zero(t, h.Cmp(expected))
}

func TestHash2(t *testing.T) {
	v1, ok := new(big.Int).SetString("1942924487407048613722894165287086275216307503549553054516710654062362616219", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("7590423656196605367096705167763685307630662983668449980730058755748798114495", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2)

	h := HashToScalarPSD4([]*big.Int{v1, v2})
	fmt.Println("hash:", h)
	expected, ok := new(big.Int).SetString("1698033436443998375091454599746043681511169858050858624941195421526973840617", 10)
	assert.True(t, ok)
	assert.Zero(t, h.Cmp(expected))
}

func TestHashToGroup(t *testing.T) {
	v1, ok := new(big.Int).SetString("930374843149285342922250391138796255744405773270013964888739305085476686494", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("6973806635473014172166696906280021443577515282950016533655912588542323187334", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2)

	x, y := HashToPointsPSD4([]*big.Int{v1, v2})
	fmt.Println("hash:", x, y)
	suite, _ := hash2curve.GetSuiteByID(hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_)

	e := suite.E.Get()
	map2Curve := suite.Map.Get(e)
	p1 := map2Curve.Map(e.Field().Elt(x))
	p2 := map2Curve.Map(e.Field().Elt(y))

	fmt.Println("to:", p1.X(), p1.Y(), p2.X(), p2.Y())

	r := e.Add(p1, p2)
	p := e.ClearCofactor(r)
	fmt.Println("p", p.X(), p.Y())
}

func TestHash4ToGroup(t *testing.T) {
	v1, ok := new(big.Int).SetString("6505909730622353745938032016428508336624262595753778174245067952766542829235", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("5077611398792538973475315675474929402435065550225859706713533723913180296702", 10)
	assert.True(t, ok)
	v3, ok := new(big.Int).SetString("1289606274883592404075309789793354746250297042916579618325711742384954903265", 10)
	assert.True(t, ok)
	v4, ok := new(big.Int).SetString("1094025124497438362079908804927636580889708282693209138574184553500446205955", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2, v3, v4)

	x, y := HashToPointsPSD4([]*big.Int{v1, v2, v3, v4})
	fmt.Println("hash:", x, y)
	suite, _ := hash2curve.GetSuiteByID(hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_)

	e := suite.E.Get()
	map2Curve := suite.Map.Get(e)
	p1 := map2Curve.Map(e.Field().Elt(x))
	p2 := map2Curve.Map(e.Field().Elt(y))

	fmt.Println("to:", p1.X(), p1.Y(), p2.X(), p2.Y())

	r := e.Add(p1, p2)
	p := e.ClearCofactor(r)
	fmt.Println("p", p.X(), p.Y())
}

func TestHash8ToGroup(t *testing.T) {
	v1, ok := new(big.Int).SetString("3922654116291461534428418701700673361784376122371531894752225492983570226976", 10)
	assert.True(t, ok)
	v2, ok := new(big.Int).SetString("2809994496610804284526782914739376817847735677570477357610575524893376405016", 10)
	assert.True(t, ok)
	v3, ok := new(big.Int).SetString("1412405057390453251565292684589929041790175653864362291070248420794768973315", 10)
	assert.True(t, ok)
	v4, ok := new(big.Int).SetString("6286266914685629842318637752285754484886186101086734305426228163476666718984", 10)
	assert.True(t, ok)
	v5, ok := new(big.Int).SetString("4539482362311866806927283180651657587320902150007884086868772854361055070064", 10)
	assert.True(t, ok)
	v6, ok := new(big.Int).SetString("3537107051547912330031651119607656041620026768291281181146799900343891493791", 10)
	assert.True(t, ok)
	v7, ok := new(big.Int).SetString("6493149414298279446359400220654227416054406120624463878803386465329667584466", 10)
	assert.True(t, ok)
	v8, ok := new(big.Int).SetString("1614210497623866181304482421609079408406496633013601777059921071771606211881", 10)
	assert.True(t, ok)
	fmt.Println("v:", v1, v2, v3, v4, v5, v6, v7, v8)

	x, y := HashToPointsPSD4([]*big.Int{v1, v2, v3, v4, v5, v6, v7, v8})
	fmt.Println("hash:", x, y)
	suite, _ := hash2curve.GetSuiteByID(hash2curve.EdBLS12377_XMDSHA512_ELL2_RO_)

	e := suite.E.Get()
	map2Curve := suite.Map.Get(e)
	p1 := map2Curve.Map(e.Field().Elt(x))
	p2 := map2Curve.Map(e.Field().Elt(y))

	fmt.Println("to:", p1.X(), p1.Y(), p2.X(), p2.Y())

	r := e.Add(p1, p2)
	p := e.ClearCofactor(r)
	fmt.Println("p", p.X(), p.Y())
}
