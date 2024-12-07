package mapping

import (
	"fmt"
	"math/big"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type wcEll2s struct {
	E C.WC
	D GF.Elt
}

func (m wcEll2s) String() string { return fmt.Sprintf("Elligator2 for E: %v", m.E) }

func newWCEll2s(e C.WC, e0 C.T) MapToCurve {
	F := e.F
	if !F.IsZero(e.A) && !F.IsZero(e.B) { // A != 0 and  B != 0
		return &wcEll2s{e, e0.D}
	}
	panic("Curve didn't match elligator2 mapping")
}

func (m *wcEll2s) Map(u GF.Elt) C.Point {
	F := m.E.F
	a := m.E.A
	d := m.D
	two_Inv := F.Inv(F.Elt(2))
	a_half := F.Mul(a, two_Inv)
	b := m.E.B
	modulus_minus_one_div_two := new(big.Int).Div(new(big.Int).Sub(m.E.F.P(), big.NewInt(1)), big.NewInt(2))

	ur2 := F.Mul(d, F.Sqr(u))
	onePlusUr2 := F.Add(F.One().Copy(), ur2) // 1 + d * u^2
	// ensure A^2 * ur^2 != B(1 + ur^2)^2
	if F.AreEqual(F.Mul(F.Sqr(a), ur2), F.Mul(b, F.Sqr(onePlusUr2))) {
		panic("can't fech correct F")
	}

	onePlusUr2_Inv := F.Inv(onePlusUr2)
	v := F.Neg(F.Mul(a, onePlusUr2_Inv))
	v2 := F.Sqr(v)
	e := F.Exp(F.Add(F.Add(F.Mul(v2, v), F.Mul(a, v2)), F.Mul(b, v)), modulus_minus_one_div_two)

	x := F.Sub(F.Mul(e, v), F.Mul(F.Sub(F.One().Copy(), e), a_half))
	x2 := F.Sqr(x)
	x3 := F.Mul(x2, x)

	rhs := F.Add(F.Add(x3, F.Mul(a, x2)), F.Mul(b, x))
	sqrt := F.Sqrt(rhs)
	sign := F.Sgn0(sqrt)

	if sign == 0 {
		sqrt = F.Neg(sqrt)
	}

	y := F.Mul(e, sqrt)

	return m.E.NewPoint(x, y)
}
