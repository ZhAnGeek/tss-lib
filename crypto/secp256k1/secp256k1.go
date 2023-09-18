/* btckeygenie v1.0.0
 * https://github.com/vsergeev/btckeygenie
 * License: MIT
 */

package secp256k1

import (
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

type Secp256k1Curve struct {
	*btcec.KoblitzCurve
}

// ScalarMult computes Q = k * P on EllipticCurve ec.
func (ec *Secp256k1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	/* Note: this function is not constant time, due to the branching nature of
	 * the underlying point Add() function. */

	/* Montgomery Ladder Point Multiplication
	 *
	 * Implementation based on pseudocode here:
	 * See https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder */
	var R0X *big.Int = new(big.Int).SetUint64(0)
	var R0Y *big.Int = new(big.Int).SetUint64(0)

	R1X := new(big.Int).Set(Bx)
	R1Y := new(big.Int).Set(By)

	K := new(big.Int).SetBytes(k)
	K = K.Mod(K, ec.Params().N)
	for i := ec.N.BitLen() - 1; i >= 0; i-- {
		if K.Bit(i) == 0 {
			R1X, R1Y = ec.Add(R0X, R0Y, R1X, R1Y)
			R0X, R0Y = ec.Add(R0X, R0Y, R0X, R0Y)
		} else {
			R0X, R0Y = ec.Add(R0X, R0Y, R1X, R1Y)
			R1X, R1Y = ec.Add(R1X, R1Y, R1X, R1Y)
		}
	}

	return R0X, R0Y
}

// ScalarBaseMult computes Q = k * G on EllipticCurve ec.
func (ec *Secp256k1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return ec.ScalarMult(ec.Gx, ec.Gy, k)
}

// Params returns the parameters for the curve.
func (curve *Secp256k1Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// S256 returns a Curve which implements secp256k1.
func S256() *Secp256k1Curve {
	return &Secp256k1Curve{btcec.S256()}
}
