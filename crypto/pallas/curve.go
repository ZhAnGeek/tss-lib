//
// Copyright Binance, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"sync"
)

var (
	k256Initonce sync.Once
	k256         Curve

	bls12381g1Initonce sync.Once
	bls12381g1         Curve

	bls12381g2Initonce sync.Once
	bls12381g2         Curve

	bls12377g1Initonce sync.Once
	bls12377g1         Curve

	bls12377g2Initonce sync.Once
	bls12377g2         Curve

	p256Initonce sync.Once
	p256         Curve

	ed25519Initonce sync.Once
	ed25519         Curve

	pallasInitonce sync.Once
	pallas         Curve
)

const (
	K256Name       = "secp256k1"
	BLS12381G1Name = "BLS12381G1"
	BLS12381G2Name = "BLS12381G2"
	BLS12831Name   = "BLS12831"
	P256Name       = "P-256"
	ED25519Name    = "ed25519"
	PallasName     = "pallas"
	BLS12377G1Name = "BLS12377G1"
	BLS12377G2Name = "BLS12377G2"
	BLS12377Name   = "BLS12377"
)

const scalarBytes = 32

// Scalar represents an element of the scalar field \mathbb{F}_q
// of the elliptic curve construction.
type Scalar interface {
	// Random returns a random scalar using the provided reader
	// to retrieve bytes
	Random(reader io.Reader) Scalar
	// Hash the specific bytes in a manner to yield a
	// uniformly distributed scalar
	Hash(bytes []byte) Scalar
	// Zero returns the additive identity element
	Zero() Scalar
	// One returns the multiplicative identity element
	One() Scalar
	// IsZero returns true if this element is the additive identity element
	IsZero() bool
	// IsOne returns true if this element is the multiplicative identity element
	IsOne() bool
	// IsOdd returns true if this element is odd
	IsOdd() bool
	// IsEven returns true if this element is even
	IsEven() bool
	// New returns an element with the value equal to `value`
	New(value int) Scalar
	// Cmp returns
	// -2 if this element is in a different field than rhs
	// -1 if this element is less than rhs
	// 0 if this element is equal to rhs
	// 1 if this element is greater than rhs
	Cmp(rhs Scalar) int
	// Square returns element*element
	Square() Scalar
	// Double returns element+element
	Double() Scalar
	// Invert returns element^-1 mod p
	Invert() (Scalar, error)
	// Sqrt computes the square root of this element if it exists.
	Sqrt() (Scalar, error)
	// Cube returns element*element*element
	Cube() Scalar
	// Add returns element+rhs
	Add(rhs Scalar) Scalar
	// Sub returns element-rhs
	Sub(rhs Scalar) Scalar
	// Mul returns element*rhs
	Mul(rhs Scalar) Scalar
	// MulAdd returns element * y + z mod p
	MulAdd(y, z Scalar) Scalar
	// Div returns element*rhs^-1 mod p
	Div(rhs Scalar) Scalar
	// Neg returns -element mod p
	Neg() Scalar
	// SetBigInt returns this element set to the value of v
	SetBigInt(v *big.Int) (Scalar, error)
	// BigInt returns this element as a big integer
	BigInt() *big.Int
	// Point returns the associated point for this scalar
	Point() Point
	// Bytes returns the canonical byte representation of this scalar
	Bytes() []byte
	// SetBytes creates a scalar from the canonical representation expecting the exact number of bytes needed to represent the scalar
	SetBytes(bytes []byte) (Scalar, error)
	// SetBytesWide creates a scalar expecting double the exact number of bytes needed to represent the scalar which is reduced by the modulus
	SetBytesWide(bytes []byte) (Scalar, error)
	// Clone returns a cloned Scalar of this value
	Clone() Scalar
}

type PairingScalar interface {
	Scalar
	SetPoint(p Point) PairingScalar
}

func unmarshalScalar(input []byte) (*Curve, []byte, error) {
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	name := string(input[:i])
	curve := GetCurveByName(name)
	if curve == nil {
		return nil, nil, fmt.Errorf("unrecognized curve")
	}
	return curve, input[i+1:], nil
}

func scalarMarshalBinary(scalar Scalar) ([]byte, error) {
	// All scalars are 32 bytes long
	// The last 32 bytes are the actual value
	// The first remaining bytes are the curve name
	// separated by a colon
	name := []byte(scalar.Point().CurveName())
	output := make([]byte, len(name)+1+scalarBytes)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func scalarUnmarshalBinary(input []byte) (Scalar, error) {
	// All scalars are 32 bytes long
	// The first 32 bytes are the actual value
	// The remaining bytes are the curve name
	if len(input) < scalarBytes+1+len(P256Name) {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sc, data, err := unmarshalScalar(input)
	if err != nil {
		return nil, err
	}
	return sc.Scalar.SetBytes(data)
}

func scalarMarshalText(scalar Scalar) ([]byte, error) {
	// All scalars are 32 bytes long
	// For text encoding we put the curve name first for readability
	// separated by a colon, then the hex encoding of the scalar
	// which avoids the base64 weakness with strict mode or not
	name := []byte(scalar.Point().CurveName())
	output := make([]byte, len(name)+1+scalarBytes*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	_ = hex.Encode(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func scalarUnmarshalText(input []byte) (Scalar, error) {
	if len(input) < scalarBytes*2+len(P256Name)+1 {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	curve, data, err := unmarshalScalar(input)
	if err != nil {
		return nil, err
	}
	var t [scalarBytes]byte
	_, err = hex.Decode(t[:], data)
	if err != nil {
		return nil, err
	}
	return curve.Scalar.SetBytes(t[:])
}

func scalarMarshalJson(scalar Scalar) ([]byte, error) {
	m := make(map[string]string, 2)
	m["type"] = scalar.Point().CurveName()
	m["value"] = hex.EncodeToString(scalar.Bytes())
	return json.Marshal(m)
}

func scalarUnmarshalJson(input []byte) (Scalar, error) {
	var m map[string]string

	err := json.Unmarshal(input, &m)
	if err != nil {
		return nil, err
	}
	curve := GetCurveByName(m["type"])
	if curve == nil {
		return nil, fmt.Errorf("invalid type")
	}
	s, err := hex.DecodeString(m["value"])
	if err != nil {
		return nil, err
	}
	S, err := curve.Scalar.SetBytes(s)
	if err != nil {
		return nil, err
	}
	return S, nil
}

// Point represents an elliptic curve point
type Point interface {
	Random(reader io.Reader) Point
	Hash(bytes []byte) Point
	Identity() Point
	Generator() Point
	IsIdentity() bool
	IsNegative() bool
	IsOnCurve() bool
	Double() Point
	Scalar() Scalar
	Neg() Point
	Add(rhs Point) Point
	Sub(rhs Point) Point
	Mul(rhs Scalar) Point
	Equal(rhs Point) bool
	Set(x, y *big.Int) (Point, error)
	ToAffineCompressed() []byte
	ToAffineUncompressed() []byte
	FromAffineCompressed(bytes []byte) (Point, error)
	FromAffineUncompressed(bytes []byte) (Point, error)
	CurveName() string
	SumOfProducts(points []Point, scalars []Scalar) Point
}

type PairingPoint interface {
	Point
	OtherGroup() PairingPoint
	Pairing(rhs PairingPoint) Scalar
	MultiPairing(...PairingPoint) Scalar
}

func pointMarshalBinary(point Point) ([]byte, error) {
	// Always stores points in compressed form
	// The first bytes are the curve name
	// separated by a colon followed by the compressed point
	// bytes
	t := point.ToAffineCompressed()
	name := []byte(point.CurveName())
	output := make([]byte, len(name)+1+len(t))
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(output)-len(t):], t)
	return output, nil
}

func pointUnmarshalBinary(input []byte) (Point, error) {
	if len(input) < scalarBytes+1+len(P256Name) {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	name := string(input[:i])
	curve := GetCurveByName(name)
	if curve == nil {
		return nil, fmt.Errorf("unrecognized curve")
	}
	return curve.Point.FromAffineCompressed(input[i+1:])
}

func pointMarshalText(point Point) ([]byte, error) {
	// Always stores points in compressed form
	// The first bytes are the curve name
	// separated by a colon followed by the compressed point
	// bytes
	t := point.ToAffineCompressed()
	name := []byte(point.CurveName())
	output := make([]byte, len(name)+1+len(t)*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	hex.Encode(output[len(output)-len(t)*2:], t)
	return output, nil
}

func pointUnmarshalText(input []byte) (Point, error) {
	if len(input) < scalarBytes*2+1+len(P256Name) {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	name := string(input[:i])
	curve := GetCurveByName(name)
	if curve == nil {
		return nil, fmt.Errorf("unrecognized curve")
	}
	buffer := make([]byte, (len(input)-i)/2)
	_, err := hex.Decode(buffer, input[i+1:])
	if err != nil {
		return nil, err
	}
	return curve.Point.FromAffineCompressed(buffer)
}

func pointMarshalJson(point Point) ([]byte, error) {
	m := make(map[string]string, 2)
	m["type"] = point.CurveName()
	m["value"] = hex.EncodeToString(point.ToAffineCompressed())
	return json.Marshal(m)
}

func pointUnmarshalJson(input []byte) (Point, error) {
	var m map[string]string

	err := json.Unmarshal(input, &m)
	if err != nil {
		return nil, err
	}
	curve := GetCurveByName(m["type"])
	if curve == nil {
		return nil, fmt.Errorf("invalid type")
	}
	p, err := hex.DecodeString(m["value"])
	if err != nil {
		return nil, err
	}
	P, err := curve.Point.FromAffineCompressed(p)
	if err != nil {
		return nil, err
	}
	return P, nil
}

// Curve represents a named elliptic curve with a scalar field and point group
type Curve struct {
	Scalar Scalar
	Point  Point
	Name   string
}

func (c Curve) ScalarBaseMult(sc Scalar) Point {
	return c.Point.Generator().Mul(sc)
}

func (c Curve) NewGeneratorPoint() Point {
	return c.Point.Generator()
}

func (c Curve) NewIdentityPoint() Point {
	return c.Point.Identity()
}

func (c Curve) NewScalar() Scalar {
	return c.Scalar.Zero()
}

// ToEllipticCurve returns the equivalent of this curve as the go interface `elliptic.Curve`
func (c Curve) ToEllipticCurve() (elliptic.Curve, error) {
	err := fmt.Errorf("can't convert %s", c.Name)
	switch c.Name {
	case BLS12381G1Name:
		return nil, err
	case BLS12381G2Name:
		return nil, err
	case BLS12831Name:
		return nil, err
	case ED25519Name:
		return nil, err
	case PallasName:
		return nil, err
	case BLS12377G1Name:
		return nil, err
	case BLS12377G2Name:
		return nil, err
	case BLS12377Name:
		return nil, err
	default:
		return nil, err
	}
}

// PairingCurve represents a named elliptic curve
// that supports pairings
type PairingCurve struct {
	Scalar  PairingScalar
	PointG1 PairingPoint
	PointG2 PairingPoint
	GT      Scalar
	Name    string
}

func (c PairingCurve) ScalarG1BaseMult(sc Scalar) PairingPoint {
	return c.PointG1.Generator().Mul(sc).(PairingPoint)
}

func (c PairingCurve) ScalarG2BaseMult(sc Scalar) PairingPoint {
	return c.PointG2.Generator().Mul(sc).(PairingPoint)
}

func (c PairingCurve) NewG1GeneratorPoint() PairingPoint {
	return c.PointG1.Generator().(PairingPoint)
}

func (c PairingCurve) NewG2GeneratorPoint() PairingPoint {
	return c.PointG2.Generator().(PairingPoint)
}

func (c PairingCurve) NewG1IdentityPoint() PairingPoint {
	return c.PointG1.Identity().(PairingPoint)
}

func (c PairingCurve) NewG2IdentityPoint() PairingPoint {
	return c.PointG2.Identity().(PairingPoint)
}

func (c PairingCurve) NewScalar() PairingScalar {
	return c.Scalar.Zero().(PairingScalar)
}

// GetCurveByName returns the correct `Curve` given the name
func GetCurveByName(name string) *Curve {
	switch name {
	case PallasName:
		return PALLAS()
	default:
		return nil
	}
}

func PALLAS() *Curve {
	pallasInitonce.Do(pallasInit)
	return &pallas
}

func pallasInit() {
	pallas = Curve{
		Scalar: new(ScalarPallas).Zero(),
		Point:  new(PointPallas).Identity(),
		Name:   PallasName,
	}
}

func expandMsgXmd(h hash.Hash, msg, domain []byte, outLen int) ([]byte, error) {
	domainLen := uint8(len(domain))
	if domainLen > 255 {
		return nil, fmt.Errorf("invalid domain length")
	}
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen], nil
}

func bhex(s string) *big.Int {
	r, _ := new(big.Int).SetString(s, 16)
	return r
}

type sswuParams struct {
	Params          *elliptic.CurveParams
	C1, C2, A, B, Z *big.Int
}

// sumOfProductsPippenger implements a version of Pippenger's algorithm.
//
// The algorithm works as follows:
//
// Let `n` be a number of point-scalar pairs.
// Let `w` be a window of bits (6..8, chosen based on `n`, see cost factor).
//
//  1. Prepare `2^(w-1) - 1` buckets with indices `[1..2^(w-1))` initialized with identity points.
//     Bucket 0 is not needed as it would contain points multiplied by 0.
//  2. Convert scalars to a radix-`2^w` representation with signed digits in `[-2^w/2, 2^w/2]`.
//     Note: only the last digit may equal `2^w/2`.
//  3. Starting with the last window, for each point `i=[0..n)` add it to a a bucket indexed by
//     the point's scalar's value in the window.
//  4. Once all points in a window are sorted into buckets, add buckets by multiplying each
//     by their index. Efficient way of doing it is to start with the last bucket and compute two sums:
//     intermediate sum from the last to the first, and the full sum made of all intermediate sums.
//  5. Shift the resulting sum of buckets by `w` bits by using `w` doublings.
//  6. Add to the return value.
//  7. Repeat the loop.
//
// Approximate cost w/o wNAF optimizations (A = addition, D = doubling):
//
// ```ascii
// cost = (n*A + 2*(2^w/2)*A + w*D + A)*256/w
//
//	      |          |       |     |   |
//	      |          |       |     |   looping over 256/w windows
//	      |          |       |     adding to the result
//	sorting points   |       shifting the sum by w bits (to the next window, starting from last window)
//	one by one       |
//	into buckets     adding/subtracting all buckets
//	                 multiplied by their indexes
//	                 using a sum of intermediate sums
//
// ```
//
// For large `n`, dominant factor is (n*256/w) additions.
// However, if `w` is too big and `n` is not too big, then `(2^w/2)*A` could dominate.
// Therefore, the optimal choice of `w` grows slowly as `n` grows.
//
// # For constant time we use a fixed window of 6
//
// This algorithm is adapted from section 4 of <https://eprint.iacr.org/2012/549.pdf>.
// and https://cacr.uwaterloo.ca/techreports/2010/cacr2010-26.pdf
func sumOfProductsPippenger(points []Point, scalars []*big.Int) Point {
	if len(points) != len(scalars) {
		return nil
	}

	const w = 6

	bucketSize := (1 << w) - 1
	windows := make([]Point, 255/w+1)
	for i := range windows {
		windows[i] = points[0].Identity()
	}
	bucket := make([]Point, bucketSize)

	for j := 0; j < len(windows); j++ {
		for i := 0; i < bucketSize; i++ {
			bucket[i] = points[0].Identity()
		}

		for i := 0; i < len(scalars); i++ {
			index := bucketSize & int(new(big.Int).Rsh(scalars[i], uint(w*j)).Int64())
			if index != 0 {
				bucket[index-1] = bucket[index-1].Add(points[i])
			}
		}

		acc, sum := windows[j].Identity(), windows[j].Identity()

		for i := bucketSize - 1; i >= 0; i-- {
			sum = sum.Add(bucket[i])
			acc = acc.Add(sum)
		}
		windows[j] = acc
	}

	acc := windows[0].Identity()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < w; j++ {
			acc = acc.Double()
		}
		acc = acc.Add(windows[i])
	}
	return acc
}
