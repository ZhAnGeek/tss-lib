package bls12377

import (
	"crypto/elliptic"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
)

var Modulus, _ = new(big.Int).SetString("8444461749428370424248824938781546531375899335154063827935233455917409239041", 10)

func HashToCurve(msg string) bls.G1Affine {
	g, err := bls.HashToG1([]byte(msg), nil)
	if err != nil {
		panic("failed on hashing message to curve")
	}
	return g
}

// TwistedEdwardsCurve CurveParams curve parameters: ax^2 + y^2 = 1 + d*x^2*y^2
type TwistedEdwardsCurve struct {
	*elliptic.CurveParams
	inner twistededwards.CurveParams
}

func (curve *TwistedEdwardsCurve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve returns bool to say if the point (x,y) is on elliptic
func (curve *TwistedEdwardsCurve) IsOnCurve(x *big.Int, y *big.Int) bool {
	p1 := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(x), *new(fr.Element).SetBigInt(y))
	return p1.IsOnCurve()
}

// Add return a point addition on elliptic
func (curve *TwistedEdwardsCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	p1 := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(x1), *new(fr.Element).SetBigInt(y1))
	p2 := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(x2), *new(fr.Element).SetBigInt(y2))
	pAdd := new(twistededwards.PointAffine).Add(&p1, &p2)
	return pAdd.X.BigInt(new(big.Int)), pAdd.Y.BigInt(new(big.Int))
}

// Double return a point doubling on elliptic
func (curve *TwistedEdwardsCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p1 := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(x1), *new(fr.Element).SetBigInt(y1))
	pDouble := p1.Double(&p1)
	return pDouble.X.BigInt(new(big.Int)), pDouble.Y.BigInt(new(big.Int))
}

// ScalarMult returns k*(x1,y1) on elliptic over BLS12_377
func (curve *TwistedEdwardsCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	p1 := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(x1), *new(fr.Element).SetBigInt(y1))
	pMul := p1.ScalarMultiplication(&p1, new(big.Int).SetBytes(k))
	return pMul.X.BigInt(new(big.Int)), pMul.Y.BigInt(new(big.Int))
}

// ScalarBaseMult returns k*basePoint on elliptic over BLS12_377
func (curve *TwistedEdwardsCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	// basePoint := twistededwards.NewPointAffine(curve.inner.Base.X, curve.inner.Base.Y)
	basePoint := twistededwards.NewPointAffine(*new(fr.Element).SetBigInt(curve.Gx), *new(fr.Element).SetBigInt(curve.Gy))
	pMul := basePoint.ScalarMultiplication(&basePoint, new(big.Int).SetBytes(k))
	return pMul.X.BigInt(new(big.Int)), pMul.Y.BigInt(new(big.Int))
}

func (curve *TwistedEdwardsCurve) init() {
	// Curve parameters taken from https://docs.rs/ark-ed-on-bls12-377/latest/ark_ed_on_bls12_377/
	curve.inner = twistededwards.GetEdwardsCurve()

	curve.N = new(big.Int).Set(&curve.inner.Order)

	// ZEXE
	// curve.Gx, curve.Gy = new(big.Int), new(big.Int)
	// curve.inner.Base.X.BigInt(curve.Gx)
	// curve.inner.Base.Y.BigInt(curve.Gy)

	// ALEO https://github.com/AleoNet/snarkVM/blob/6142144d67d66c5c30beeac848ae4996d09c47d9/console/network/src/mainnet_v0.rs#L38
	gx, _ := new(big.Int).SetString("522678458525321116977504528531602186870683848189190546523208313015552693483", 10)
	gy, _ := new(big.Int).SetString("4625467284263880392848236339834904393692054417272076479096796531274999498606", 10)
	curve.Gx = new(big.Int).Set(gx)
	curve.Gy = new(big.Int).Set(gy)

	curve.BitSize = Modulus.BitLen()
	curve.P = Modulus
}

func EdBls12377Curve() *TwistedEdwardsCurve {
	curve := new(TwistedEdwardsCurve)
	curve.CurveParams = new(elliptic.CurveParams)
	curve.init()
	return curve
}
