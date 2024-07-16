package edwards25519

import (
	"crypto/elliptic"
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/Safulet/tss-lib-private/v2/common"
	"math/big"
)

var (
	P = Edwards25519().Params().P
)

func NewPoint(x, y *big.Int) (*edwards25519.Point, error) {
	if x == nil || y == nil {
		return edwards25519.NewIdentityPoint(), nil
	}
	xMod := new(big.Int).Mod(x, P)
	yMod := new(big.Int).Mod(y, P)

	xFe, err := new(field.Element).SetBytes(common.ReverseBytes(common.PadToLengthBytesInPlace(xMod.Bytes(), 32)))
	if err != nil {
		return nil, err
	}
	yFe, err := new(field.Element).SetBytes(common.ReverseBytes(common.PadToLengthBytesInPlace(yMod.Bytes(), 32)))
	if err != nil {
		return nil, err
	}
	zFe := new(field.Element).One()
	tFe := new(field.Element).Multiply(xFe, yFe)
	v, err := edwards25519.NewIdentityPoint().SetExtendedCoordinates(xFe, yFe, zFe, tFe)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func ToAffine(p *edwards25519.Point) (x, y *big.Int) {
	xFe, yFe, zFe, _ := p.ExtendedCoordinates()
	zInvFe := new(field.Element).Invert(zFe)
	xFe.Multiply(xFe, zInvFe)
	yFe.Multiply(yFe, zInvFe)
	x = new(big.Int).SetBytes(common.ReverseBytes(xFe.Bytes()))
	y = new(big.Int).SetBytes(common.ReverseBytes(yFe.Bytes()))
	return x, y
}

type Curve struct {
	*elliptic.CurveParams
}

func Edwards25519() elliptic.Curve {
	// The prime modulus of the field.
	// P = 2^255-19
	params := new(elliptic.CurveParams)
	params.P = new(big.Int)
	params.P.SetBit(big.NewInt(0), 255, 1).Sub(params.P, big.NewInt(19))

	// The prime order for the base point.
	// N = 2^252 + 27742317777372353535851937790883648493
	qs, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	params.N = new(big.Int)
	params.N.SetBit(big.NewInt(0), 252, 1).Add(params.N, qs) // AKA Q

	// The base point.
	params.Gx = new(big.Int)
	params.Gx.SetString("151122213495354007725011514095885315"+
		"11454012693041857206046113283949847762202", 10)
	params.Gy = new(big.Int)
	params.Gy.SetString("463168356949264781694283940034751631"+
		"41307993866256225615783033603165251855960", 10)

	params.BitSize = 256
	// params.H = 8

	curve := Curve{params}
	return curve
}

func (curve Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve Curve) IsOnCurve(x, y *big.Int) bool {
	p, err := NewPoint(x, y)
	if err != nil {
		return false
	}
	_, err = edwards25519.NewIdentityPoint().SetBytes(p.Bytes())
	return err == nil
}

func (curve Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1, err := NewPoint(x1, y1)
	if err != nil {
		return nil, nil
	}
	p2, err := NewPoint(x2, y2)
	if err != nil {
		return nil, nil
	}
	v := edwards25519.NewIdentityPoint().Add(p1, p2)
	x, y = ToAffine(v)
	return x, y
}

func (curve Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.Add(x1, y1, x1, y1)
}

func (curve Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	if k == nil {
		return nil, nil
	}
	p, err := NewPoint(x1, y1)
	if err != nil {
		return nil, nil
	}
	r, err := edwards25519.NewScalar().SetCanonicalBytes(common.ReverseBytes(common.PadToLengthBytesInPlace(k, 32)))
	if err != nil {
		return nil, nil
	}
	v := edwards25519.NewIdentityPoint().ScalarMult(r, p)
	x, y = ToAffine(v)
	return x, y
}

func (curve Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	r, err := edwards25519.NewScalar().SetCanonicalBytes(common.ReverseBytes(common.PadToLengthBytesInPlace(k, 32)))
	if err != nil {
		return nil, nil
	}
	v := edwards25519.NewIdentityPoint().ScalarBaseMult(r)
	x, y = ToAffine(v)
	return x, y
}
