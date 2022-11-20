// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bls12381

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

func getBLSSignatureCipherSuiteID(H2cSuiteId, ScTag []byte) []byte {
	var suiteID []byte
	suiteID = append(suiteID, "BLS_SIG_"...)
	suiteID = append(suiteID, H2cSuiteId...)
	suiteID = append(suiteID, ScTag...)
	suiteID = append(suiteID, '_')

	return suiteID
}

func getHashTOCurveSuiteID(CurveId, HashId, MapId, EncVar []byte) []byte {
	var suiteID []byte
	suiteID = append(suiteID, CurveId...)
	suiteID = append(suiteID, '_')
	suiteID = append(suiteID, HashId...)
	suiteID = append(suiteID, '_')
	suiteID = append(suiteID, MapId...)
	suiteID = append(suiteID, '_')
	suiteID = append(suiteID, EncVar...)
	suiteID = append(suiteID, '_')

	return suiteID
}

func getHashID(ExpTag, HashName []byte) []byte {
	var hashID []byte
	hashID = append(hashID, ExpTag...)
	hashID = append(hashID, ':')
	hashID = append(hashID, HashName...)

	return hashID
}

func GetBLSSignatureSuiteG1() []byte {
	HashID := getHashID([]byte("XMD"), []byte("SHA-256"))
	H2cSuiteID := getHashTOCurveSuiteID([]byte("G2Curve"), HashID, []byte("SSWU"), []byte("RO"))
	ScTag := []byte("POP")
	return getBLSSignatureCipherSuiteID(H2cSuiteID, ScTag)
}

func GetBLSSignatureSuiteG2() []byte {
	HashID := getHashID([]byte("XMD"), []byte("SHA-256"))
	H2cSuiteID := getHashTOCurveSuiteID([]byte("BLS12381G2"), HashID, []byte("SSWU"), []byte("RO"))
	ScTag := []byte("POP")
	return getBLSSignatureCipherSuiteID(H2cSuiteID, ScTag)
}

// strXor returns the bitwise XOR of the two strings
// ref https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#section-4
// adapted from Bytes() in https://github.com/lukechampine/fastxor/blob/master/xor.go
func strXor(a, b []byte) []byte {
	var c []byte

	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return c
	}
	c = make([]byte, n)
	_ = c[n-1]
	_ = a[n-1]
	_ = b[n-1]
	for i := 0; i < n; i++ {
		c[i] = a[i] ^ b[i]
	}

	return c
}

// I2OSP converts a nonnegative integer to an octet string of a specified length
// ref https://datatracker.ietf.org/doc/html/rfc8017#section-4
// Input:
// x, nonnegative integer to be converted
// xLen, intended length of the resulting octet string
func I2OSP(x, xLen int) ([]byte, error) {
	xB := big.NewInt(int64(x))
	if xB.Cmp(zero) == -1 || xB.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(8*xLen))) != -1 {
		return nil, errors.New(fmt.Sprintf("I2OSP overflow %s, %d", xB.String(), xLen))
	}
	return PadToLengthBytesInPlace(xB.Bytes(), xLen), nil
}

// OS2IP converts an octet string to a nonnegative integer
// ref https://datatracker.ietf.org/doc/html/rfc8017#section-4
// Input:
// x, octet string to be converted
func OS2IP(x []byte) *big.Int {
	val := new(big.Int).SetBytes(x)
	return val
}

// expandMessageXmd over sha256
// ref https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#section-5.4.1
// Input:
// msg, a byte string
// DST, domain seperate tag, a byte string of at most 255 bytes
// lenInBytes, the length of the requested output in bytes
func expandMessageXmd(msg, DST []byte, lenInBytes int) ([]byte, error) {
	bInBytes := sha256.Size
	rInBytes := sha256.BlockSize

	ell := (lenInBytes + bInBytes - 1) / bInBytes
	if ell > 255 {
		return nil, errors.New(fmt.Sprintf("expand_message: ell=%d out of range", ell))
	}

	tail, err := I2OSP(len(DST), 1)
	if err != nil {
		return nil, err
	}
	DSTPrime := append(DST, tail...)
	ZPad, err := I2OSP(0, rInBytes)
	if err != nil {
		return nil, err
	}
	LIBStr, err := I2OSP(lenInBytes, 2)
	if err != nil {
		return nil, err
	}
	var msgPrime []byte
	{
		msgPrime = append(msgPrime, ZPad...)
		msgPrime = append(msgPrime, msg...)
		msgPrime = append(msgPrime, LIBStr...)
		val, err := I2OSP(0, 1)
		if err != nil {
			return nil, err
		}
		msgPrime = append(msgPrime, val...)
		msgPrime = append(msgPrime, DSTPrime...)
	}
	bVals := make([][32]byte, ell+1)
	bVals[0] = sha256.Sum256(msgPrime)
	{
		var msgPrimeNew []byte
		msgPrimeNew = append(msgPrimeNew, bVals[0][:]...)
		val, err := I2OSP(1, 1)
		if err != nil {
			return nil, err
		}
		msgPrimeNew = append(msgPrimeNew, val...)
		msgPrimeNew = append(msgPrimeNew, DSTPrime...)
		bVals[1] = sha256.Sum256(msgPrimeNew)
	}
	for i := 2; i <= ell; i++ {
		var msgPrimeNew []byte
		bXor := strXor(bVals[0][:], bVals[i-1][:])
		msgPrimeNew = append(msgPrimeNew, bXor...)
		val, err := I2OSP(i, 1)
		if err != nil {
			return nil, err
		}
		msgPrimeNew = append(msgPrimeNew, val...)
		msgPrimeNew = append(msgPrimeNew, DSTPrime...)
		bVals[i] = sha256.Sum256(msgPrimeNew)
	}
	var uniformBytes []byte
	for i := 1; i <= ell; i++ {
		uniformBytes = append(uniformBytes, bVals[i][:]...)
	}

	return uniformBytes[:lenInBytes], nil
}

// hashToField hashed to an element of the extension field
// ref https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-09#section-5.3
func hashToField(msg []byte, count int, DST []byte, p *big.Int, m, L int) ([][]*big.Int, error) {
	lenInBytes := count * m * L
	uniformBytes, err := expandMessageXmd(msg, DST, lenInBytes)
	if err != nil {
		return nil, err
	}
	uVals := make([][]*big.Int, count)
	for i := 0; i < count; i++ {
		eVals := make([]*big.Int, m)
		for j := 0; j < m; j++ {
			elmOffset := L * (j + i*m)
			tv := uniformBytes[elmOffset:(elmOffset + L)]
			eJ := OS2IP(tv)
			eVals[j] = new(big.Int).Mod(eJ, p)
		}
		uVals[i] = eVals
	}

	return uVals, nil
}

func HashToPointG1(message []byte) (*bls.PointG1, error) {
	DST := GetBLSSignatureSuiteG1()
	Fs, err := hashToField(message, 1, DST, modulus.big(), 1, 64)
	if err != nil {
		return nil, err
	}
	g1 := bls.NewG1()
	FBytes := make([]byte, 48)
	Fs[0][0].FillBytes(FBytes)
	dG1, err := g1.MapToCurve(FBytes)
	if err != nil {
		return nil, err
	}
	return dG1, nil
}

func HashToPointG2(message []byte) (*bls.PointG2, error) {
	DST := GetBLSSignatureSuiteG2()
	Fs, err := hashToField(message, 1, DST, modulus.big(), 1, 64)
	if err != nil {
		return nil, err
	}
	g2 := bls.NewG2()
	FBytes := make([]byte, 96)
	Fs[0][0].FillBytes(FBytes)
	dG2, err := g2.MapToCurve(FBytes)
	if err != nil {
		return nil, err
	}
	return dG2, nil
}
