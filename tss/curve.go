// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"reflect"

	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/crypto/curve25519"
	"github.com/Safulet/tss-lib-private/v2/crypto/edwards25519"
	"github.com/Safulet/tss-lib-private/v2/crypto/secp256k1"
	"github.com/Safulet/tss-lib-private/v2/crypto/starkcurve"

	curves "github.com/Safulet/tss-lib-private/v2/crypto/pallas"
)

type CurveName string

const (
	Secp256k1  CurveName = "secp256k1"
	Nist256p1  CurveName = "nist256p1" // a.k.a secp256r1
	Ed25519    CurveName = "ed25519"
	BLS12381G2 CurveName = "bls12381g2"
	BLS12381G1 CurveName = "bls12381g1"
	C25519     CurveName = "curve25519"
	PAllas     CurveName = "pallas"
	Starkcurve CurveName = "starkcurve"
)

var (
	ec       elliptic.Curve
	registry map[CurveName]elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = secp256k1.S256()

	registry = make(map[CurveName]elliptic.Curve)
	registry[Secp256k1] = secp256k1.S256()
	registry[Nist256p1] = elliptic.P256()
	registry[Ed25519] = edwards25519.Edwards25519()
	registry[BLS12381G2] = bls12381.G2Curve()
	registry[BLS12381G1] = bls12381.G1Curve()
	registry[C25519] = curve25519.C25519()
	registry[PAllas] = curves.Pallas()
	registry[Starkcurve] = starkcurve.Stark()
}

func RegisterCurve(name CurveName, curve elliptic.Curve) {
	registry[name] = curve
}

// return curve, exist(bool)
func GetCurveByName(name CurveName) (elliptic.Curve, bool) {
	if val, exist := registry[name]; exist {
		return val, true
	}

	return nil, false
}

// return name, exist(bool)
func GetCurveName(curve elliptic.Curve) (CurveName, bool) {
	for name, e := range registry {
		if reflect.TypeOf(curve) == reflect.TypeOf(e) {
			return name, true
		}
	}

	return "", false
}

// SameCurve returns true if both lhs and rhs are the same known curve
func SameCurve(lhs, rhs elliptic.Curve) bool {
	lName, lOk := GetCurveName(lhs)
	rName, rOk := GetCurveName(rhs)
	if lOk && rOk {
		return lName == rName
	}
	// if lhs/rhs not exist, return false
	return false
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC() elliptic.Curve {
	return ec
}

// SetCurve sets the curve used by TSS. Must be called before Start. The default is secp256k1
// Deprecated
func SetCurve(curve elliptic.Curve) {
	if curve == nil {
		panic(errors.New("SetCurve received a nil curve"))
	}
	ec = curve
}

// secp256k1
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// starkCurve
func StarkCurve() elliptic.Curve {
	return starkcurve.Stark()
}

func P256() elliptic.Curve {
	return elliptic.P256()
}

func Edwards() elliptic.Curve {
	return edwards25519.Edwards25519()
}

func Bls12381G2() elliptic.Curve {
	return bls12381.G2Curve()
}

func Bls12381G1() elliptic.Curve {
	return bls12381.G1Curve()
}

func GetBLSCurveBySuite(suite []byte) elliptic.Curve {
	if bytes.Compare(suite, bls12381.GetBLSSignatureSuiteG1()) == 0 {
		return Bls12381G2()
	}
	return Bls12381G1()
}

func Curve25519() elliptic.Curve {
	return curve25519.C25519()
}

func Pallas() elliptic.Curve {
	return curves.Pallas()
}

func GetAllCurvesList() []elliptic.Curve {
	curvesList := []elliptic.Curve{
		S256(),
		P256(),
		Pallas(),
		Bls12381G1(),
		Bls12381G2(),
		Edwards(),
		Curve25519(),
		StarkCurve()}
	return curvesList
}
