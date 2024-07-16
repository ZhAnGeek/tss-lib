// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Curve sign and verify for test usage comes from https://github.com/NethermindEth/starknet.go

package starkcurve

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"

	fp "github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
)

const (
	// If big.Word is uint32, wordBits would be 32.
	// If big.Word is uint64, wordBits would be 64.
	// Do not work if big.Word is of other types
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes            = wordBits / 8
	N_ELEMENT_BITS_ECDSA = 251
)

// readBits encodes the absolute value of bigint as big-endian bytes. Callers
// must ensure that buf has enough space. If buf is too short the result will
// be incomplete.
func readBits(bigint *big.Int, buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	if len(buf) < (bigint.BitLen()+7)/8 {
		panic("should ensure buf bytes enough")
	}
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

// Stark Curve, see https://docs.starkware.co/starkex/crypto/stark-curve.html
// y^2 = x^3 + alpha*x + beta (mod p)
type StarkCurve struct {
	P                                  *big.Int
	N                                  *big.Int
	Alpha, Beta                        *big.Int
	Gx, Gy                             *big.Int
	BitSize                            int // the size of the underlying field
	ShiftPointx, ShiftPointy           *big.Int
	MinusShiftPointx, MinusShiftPointy *big.Int
	EcdsaMax                           *big.Int
}

func (starkCurve *StarkCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       curve.P,
		N:       curve.N,
		B:       curve.Beta,
		Gx:      curve.Gx,
		Gy:      curve.Gy,
		BitSize: curve.BitSize,
	}
}

// IsOnCurve returns true if the given (x,y) lies on the Stark Curve.
// y ^ 2 = (x^ 3 + alpha x + beta) mod P
func (starkCurve *StarkCurve) IsOnCurve(x, y *big.Int) bool {
	y2 := new(big.Int).Mul(y, y)
	y2 = y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3 = x3.Mod(x3, curve.P)
	x3 = x3.Mul(x3, x)
	x3 = x3.Mod(x3, curve.P)

	alphax := new(big.Int).Mul(curve.Alpha, x)
	x3 = x3.Add(x3, alphax)

	x3 = x3.Add(x3, curve.Beta)
	x3 = x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

// Add computes the sum of two points on the StarkCurve.
// Assumes affine form (x, y) is spread (x1 *big.Int, y1 *big.Int)
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/math_utils.py#L59)
//
// Parameters:
// - x1, y1: The coordinates of the first point as pointers to big.Int on the curve
// - x2, y2: The coordinates of the second point as pointers to big.Int on the curve
// Returns:
// - x, y: two pointers to big.Int, representing the x and y coordinates of the sum of the two input points
func (sc *StarkCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	X1 := fp.NewElement(0)
	Y1 := fp.NewElement(0)
	X1.SetInterface(x1)
	Y1.SetInterface(y1)
	point1 := &starkcurve.G1Affine{X: X1, Y: Y1}

	X2 := fp.NewElement(0)
	Y2 := fp.NewElement(0)
	X2.SetInterface(x2)
	Y2.SetInterface(y2)
	point2 := &starkcurve.G1Affine{X: X2, Y: Y2}

	pointadd := new(starkcurve.G1Affine).Add(point1, point2)

	return pointadd.X.BigInt(new(big.Int)), pointadd.Y.BigInt(new(big.Int))
}

// Double calculates the double of a point on a StarkCurve (equation y^2 = x^3 + alpha*x + beta mod p).
// Assumes affine form (x, y) is spread (x1 *big.Int, y1 *big.Int)
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/math_utils.py#L79)
//
// The function takes two pointers to big.Int values, x1 and y1, which represent the
// coordinates of the point to be doubled on the StarkCurve. It returns two pointers
// to big.Int values, x and y, which represent the coordinates of the resulting point
// after the doubling operation.
//
// Parameters:
// - x1, y1: The coordinates of the point to be doubled on the StarkCurve.
// Returns:
// - x, y: two pointers to big.Int, representing the x and y coordinates of the resulting point
func (sc *StarkCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	X := fp.NewElement(0)
	Y := fp.NewElement(0)
	X.SetInterface(x1)
	Y.SetInterface(y1)
	point := &starkcurve.G1Affine{X: X, Y: Y}
	var _p starkcurve.G1Jac
	_p.FromAffine(point)
	_p.Double(&_p)
	result := new(starkcurve.G1Affine).FromJacobian(&_p)
	return result.X.BigInt(new(big.Int)), result.Y.BigInt(new(big.Int))
}

// ScalarMult performs scalar multiplication on a point (x1, y1) with a scalar value k.
//
// Parameters:
// - x1: The x-coordinate of the point to be multiplied.
// - y1: The y-coordinate of the point to be multiplied.
// - k: The scalar value to multiply the point with.
// Returns:
// - x: The x-coordinate of the resulting point.
// - y: The y-coordinate of the resulting point.
func (sc *StarkCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	X := fp.NewElement(0)
	Y := fp.NewElement(0)
	X.SetInterface(x1)
	Y.SetInterface(y1)
	point := &starkcurve.G1Affine{X: X, Y: Y}
	result := new(starkcurve.G1Affine).ScalarMultiplication(point, new(big.Int).SetBytes(k))
	return result.X.BigInt(new(big.Int)), result.Y.BigInt(new(big.Int))
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (starkCurve *StarkCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return starkCurve.ScalarMult(curve.Gx, curve.Gy, k)
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI X9.62.
func (starkCurve *StarkCurve) Marshal(x, y *big.Int) []byte {
	byteLen := (starkCurve.BitSize + 7) >> 3
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point flag
	readBits(x, ret[1:1+byteLen])
	readBits(y, ret[1+byteLen:])
	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On error, x = nil.
func (starkCurve *StarkCurve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := (starkCurve.BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return
}

// MimicEcMultAir performs a computation on the StarkCurve struct (m * point + shift_point)
// using the same steps like the AIR.
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/signature.py#L176)
// AIR : Algebraic Intermediate Representation of computation
//
// Parameters:
// - mout: a pointer to a big.Int variable
// - x1, y1: a pointer to a big.Int point on the curve
// - x2, y2: a pointer to a big.Int point on the curve
// Returns:
// - x, y: a pointer to a big.Int point on the curve
// - err: an error if any
func (sc StarkCurve) MimicEcMultAir(mout, x1, y1, x2, y2 *big.Int) (x *big.Int, y *big.Int, err error) {
	m := new(big.Int).Set(mout)
	if m.Cmp(big.NewInt(0)) != 1 || m.Cmp(sc.EcdsaMax) != -1 {
		return x, y, fmt.Errorf("too many bits %v", m.BitLen())
	}

	psx := x2
	psy := y2
	for i := 0; i < N_ELEMENT_BITS_ECDSA; i++ {
		if psx == x1 {
			return x, y, fmt.Errorf("xs are the same")
		}
		if m.Bit(0) == 1 {
			psx, psy = sc.Add(psx, psy, x1, y1)
		}
		x1, y1 = sc.Double(x1, y1)
		m = m.Rsh(m, 1)
	}
	if m.Cmp(big.NewInt(0)) != 0 {
		return psx, psy, fmt.Errorf("m exceeds 251 bits")
	}
	return psx, psy, nil
}

// DivMod calculates the quotient and remainder of a division operation between two big integers (0 <= x < p such that (m * x) % p == n).
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/math_utils.py#L50)
//
// Parameters:
// - n: a pointer to a big integer representing the dividend
// - m: a pointer to a big integer representing the divisor
// - p: a pointer to a big integer representing the modulus
// Returns:
// - *big.Int: a pointer to a big integer representing the remainder of the division operation.
func DivMod(n, m, p *big.Int) *big.Int {
	q := new(big.Int)
	gx := new(big.Int)
	gy := new(big.Int)
	q.GCD(gx, gy, m, p)

	r := new(big.Int).Mul(n, gx)
	r = r.Mod(r, p)
	return r
}

// InvModCurveSize calculates the modulus inverse of a given big integer 'x' with respect to the StarkCurve 'sc'.
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/math_utils.py)
//
// Parameters:
// - x: The big integer to calculate the modulus inverse for
// Returns:
// - The modulus inverse of 'x' with respect to 'sc.N'
func (sc StarkCurve) InvModCurveSize(x *big.Int) *big.Int {
	return DivMod(big.NewInt(1), x, sc.N)
}

// Verify verifies the validity of the signature for a given message hash using the StarkCurve.
// (ref: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/signature.py#L217)
//
// Parameters:
// - msgHash: The message hash to be verified
// - r: The r component of the signature
// - s: The s component of the signature
// - pubX: The x-coordinate of the public key used for verification
// - pubY: The y-coordinate of the public key used for verification
// Returns:
// - bool: true if the signature is valid, false otherwise
func (sc *StarkCurve) Verify(msgHash, r, s, pubX, pubY *big.Int) (bool, error) {
	w := sc.InvModCurveSize(s)

	if s.Cmp(big.NewInt(0)) != 1 || s.Cmp(sc.N) != -1 {
		return false, errors.New("s exceeds the range (0, N)")
	}
	if r.Cmp(big.NewInt(0)) != 1 || r.Cmp(sc.EcdsaMax) != -1 {
		return false, errors.New("r exceeds the range (0, EcdsaMax)")
	}

	if w.Cmp(big.NewInt(0)) != 1 || w.Cmp(sc.EcdsaMax) != -1 {
		return false, errors.New("w exceeds the range (0, EcdsaMax)")
	}
	if msgHash.Cmp(big.NewInt(0)) != 1 || msgHash.Cmp(sc.EcdsaMax) != -1 {
		return false, errors.New("hash exceeds the range (0, EcdsaMax)")
	}
	if !sc.IsOnCurve(pubX, pubY) {
		return false, nil
	}

	zGx, zGy, err := sc.MimicEcMultAir(msgHash, sc.Gx, sc.Gy, sc.MinusShiftPointx, sc.MinusShiftPointy)
	if err != nil {
		return false, err
	}

	rQx, rQy, err := sc.MimicEcMultAir(r, pubX, pubY, sc.ShiftPointx, sc.ShiftPointy)
	if err != nil {
		return false, err
	}

	inX, inY := sc.Add(zGx, zGy, rQx, rQy)
	wBx, wBy, err := sc.MimicEcMultAir(w, inX, inY, sc.ShiftPointx, sc.ShiftPointy)
	if err != nil {
		return false, err
	}

	outX, _ := sc.Add(wBx, wBy, sc.MinusShiftPointx, sc.MinusShiftPointy)
	if r.Cmp(outX) == 0 {
		return true, nil
	} else {
		inX, inY = sc.Add(zGx, zGy, rQx, new(big.Int).Neg(rQy))
		inX, inY = sc.Add(inX, inY, sc.ShiftPointx, sc.ShiftPointy)
		inX, inY = sc.Add(inX, inY, sc.ShiftPointx, sc.ShiftPointy)
		wBx, wBy, err = sc.MimicEcMultAir(w, inX, inY, sc.ShiftPointx, sc.ShiftPointy)
		if err != nil {
			return false, err
		}

		outX, _ = sc.Add(wBx, wBy, sc.MinusShiftPointx, sc.MinusShiftPointy)
		if r.Cmp(outX) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func (sc *StarkCurve) Sign(privateKey, hash *big.Int) (*big.Int, *big.Int, error) {
	if privateKey.Cmp(big.NewInt(1)) != 1 || privateKey.Cmp(sc.N) != -1 {
		return nil, nil, errors.New("error, private key must in scope [1, orderCurve)")
	}

	if hash.Cmp(sc.EcdsaMax) >= 0 {
		return nil, nil, errors.New("error, the length of hash cannot be larger than the order of the curve")
	}

	counter := 0

	for true {
		counter++
		if counter > 1000 {
			break
		}

		k := common.GetRandomPositiveInt(sc.N)
		xKG, _ := sc.ScalarBaseMult(k.Bytes())
		r := new(big.Int).Mod(xKG, sc.N)

		if r.Cmp(big.NewInt(1)) != 1 || r.Cmp(sc.EcdsaMax) != -1 {
			continue
		}

		mRPriv := new(big.Int).Mul(r, privateKey)
		mRPriv = new(big.Int).Add(mRPriv, hash)
		mRPriv = new(big.Int).Mod(mRPriv, sc.N)

		kInv := new(big.Int).ModInverse(k, sc.N)

		s := new(big.Int).Mul(kInv, mRPriv)
		s = new(big.Int).Mod(s, sc.N)

		if s.Cmp(big.NewInt(1)) != 1 || s.Cmp(sc.N) != -1 {
			continue
		}

		sInv := new(big.Int).ModInverse(s, sc.N)

		if sInv.Cmp(big.NewInt(1)) != 1 || sInv.Cmp(sc.EcdsaMax) != -1 {
			continue
		}

		return r, s, nil
	}
	return nil, nil, errors.New("error, cannot obtain a valid signature after 1000 attempts")
}

// getYCoordinate is a function. Given X Coordinate we can get one of the Y Coordinate.
// tips: The function could return nil if impossible to find a y.
// tips: consider Neg Y if you need exact match to specific Y.
func (sc *StarkCurve) GetYCoordinate(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3 = new(big.Int).Mul(x3, x)

	alphax := new(big.Int).Mul(curve.Alpha, x)
	x3 = x3.Add(x3, alphax)

	x3 = x3.Add(x3, curve.Beta)
	x3 = x3.Mod(x3, curve.P)

	x3 = x3.ModSqrt(x3, curve.P)
	return x3
}

func (sc *StarkCurve) getRandomPrivateKey() *big.Int {
	return common.GetRandomPositiveInt(sc.N)
}

var curve = new(StarkCurve)

// # Elliptic curve parameters.
// assert 2**N_ELEMENT_BITS_ECDSA < EC_ORDER < FIELD_PRIME

func init() {
	curve.P, _ = new(big.Int).SetString("3618502788666131213697322783095070105623107215331596699973092056135872020481", 10)
	curve.N, _ = new(big.Int).SetString("3618502788666131213697322783095070105526743751716087489154079457884512865583", 10)
	curve.Alpha, _ = new(big.Int).SetString("1", 10)
	curve.Beta, _ = new(big.Int).SetString("3141592653589793238462643383279502884197169399375105820974944592307816406665", 10)
	curve.Gx, _ = new(big.Int).SetString("874739451078007766457464989774322083649278607533249481151382481072868806602", 10)
	curve.Gy, _ = new(big.Int).SetString("152666792071518830868575557812948353041420400780739481342941381225525861407", 10)
	curve.BitSize = 252
	curve.ShiftPointx, _ = new(big.Int).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	curve.ShiftPointy, _ = new(big.Int).SetString("1713931329540660377023406109199410414810705867260802078187082345529207694986", 10)
	curve.MinusShiftPointx, _ = new(big.Int).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	curve.MinusShiftPointy, _ = new(big.Int).SetString("1904571459125470836673916673895659690812401348070794621786009710606664325495", 10)
	curve.EcdsaMax, _ = new(big.Int).SetString("3618502788666131106986593281521497120414687020801267626233049500247285301248", 10) // 2^251
}

// Stark returns a StarkCurve instance
func Stark() *StarkCurve {
	return curve
}
