// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// ECPoint convenience helper
// For infinity point, coords == nil, nil, it's treated not on curve
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

var (
	eight = big.NewInt(8)
	// For ed25519 and curve25519
	eightInv = new(big.Int).ModInverse(eight, edwards.Edwards().Params().N)
)

// NewECPoint creates a new ECPoint and checks that the given coordinates are on the elliptic curve or infinity point.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if X == nil && Y == nil {
		return NewInfinityPoint(curve), nil
	}
	x1, y1 := IntInfinityCoords(curve)
	if X.Cmp(x1) == 0 && Y.Cmp(y1) == 0 {
		return NewInfinityPoint(curve), nil
	}
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

func NewInfinityPoint(curve elliptic.Curve) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{nil, nil}}
}

// NewECPointNoCurveCheck creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func (p *ECPoint) X() *big.Int {
	if p.IsInfinityPoint() {
		return nil
	}
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	if p.IsInfinityPoint() {
		return nil
	}
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Neg() *ECPoint {
	k := new(big.Int).Sub(p.curve.Params().N, big.NewInt(1))
	return p.ScalarMult(k)
}

func (p *ECPoint) Sub(p1 *ECPoint) (*ECPoint, error) {
	nP1 := p1.Neg()
	return p.Add(nP1)
}

func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	if IsInfinityCoords(p.curve, p.X(), p.Y()) {
		return p1, nil
	}
	if IsInfinityCoords(p1.curve, p1.X(), p1.Y()) {
		return p, nil
	}
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	if IsInfinityCoords(p.curve, x, y) {
		return NewInfinityPoint(p.curve), errors.New("got InfinityPoint")
	}
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	if p.IsInfinityPoint() {
		return p
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	if IsInfinityCoords(p.curve, x, y) {
		return NewInfinityPoint(p.curve)
	}
	newP, err := NewECPoint(p.curve, x, y) // it must be on the curve, no need to check.
	if err != nil {
		panic(fmt.Errorf("scalar mult to an ecpoint %s", err.Error()))
	}
	return newP
}

func (p *ECPoint) ToECDSAPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

func (p *ECPoint) IsOnCurve() bool {
	return isOnCurve(p.curve, p.coords[0], p.coords[1])
}

func (p *ECPoint) IsInfinityPoint() bool {
	return p.coords[0] == nil && p.coords[1] == nil
}

func IsInfinityCoords(curve elliptic.Curve, x, y *big.Int) bool {
	if x == nil && y == nil {
		return true
	}
	x1, y1 := IntInfinityCoords(curve)
	return x.Cmp(x1) == 0 && y.Cmp(y1) == 0
}

func IntInfinityCoords(curve elliptic.Curve) (*big.Int, *big.Int) {
	if tss.SameCurve(curve, tss.Edwards()) {
		return zero, one
	}
	if tss.SameCurve(curve, tss.Curve25519()) {
		return one, zero
	}
	return zero, zero
}

func (p *ECPoint) IsInSubGroup() bool {
	if tss.SameCurve(p.curve, tss.Edwards()) {
		p1 := p.EightInvEight()
		return p.Equals(p1)
	}
	if tss.SameCurve(p.curve, tss.Curve25519()) {
		p1 := p.EightInvEight()
		return p.Equals(p1)
	}

	return true
}

func (p *ECPoint) Curve() elliptic.Curve {
	return p.curve
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	if p.IsInfinityPoint() {
		return p2.IsInfinityPoint()
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

func (p *ECPoint) EightInvEight() *ECPoint { // TODO generalize
	return p.ScalarMult(eight).ScalarMult(eightInv)
}

func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve()
}

func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, _ := NewECPoint(curve, x, y) // it must be on the curve, no need to check.
	return p
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	return c.IsOnCurve(x, y)
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

// ----- //

func (p *ECPoint) Bytes() [2][]byte {
	var x, y *big.Int
	if !p.IsInfinityPoint() {
		x, y = p.X(), p.Y()
	} else {
		x, y = IntInfinityCoords(p.curve)
	}
	return [...][]byte{
		x.Bytes(),
		y.Bytes(),
	}
}

func NewECPointFromBytes(ec elliptic.Curve, bzs [][]byte) (*ECPoint, error) {
	x, y := new(big.Int).SetBytes(bzs[0]), new(big.Int).SetBytes(bzs[1])
	if IsInfinityCoords(ec, x, y) {
		return NewInfinityPoint(ec), nil
	}
	point, err := NewECPoint(ec, x, y)
	if err != nil {
		return nil, err
	}
	return point, nil
}

// crypto.ECPoint is not inherently json marshal-able
func (p *ECPoint) MarshalJSON() ([]byte, error) {
	ecName, ok := tss.GetCurveName(p.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", p.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: p.coords,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		p.curve = ec
	} else {
		// forward compatible, find ec from possible list
		curvesList := []elliptic.Curve{
			tss.S256(),
			tss.P256(),
			tss.Edwards()}
		for _, ec := range curvesList {
			_, err := NewECPoint(ec, p.coords[0], p.coords[1])
			if err == nil {
				p.curve = ec
			}
		}
		if p.curve == nil {
			return fmt.Errorf("cannot find a curve with given coordinates")
		}
	}

	if !p.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", p.curve)
	}

	return nil
}
