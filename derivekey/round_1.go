// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package derivekey

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/hash2curve"
	"github.com/Safulet/tss-lib-private/crypto/zkp/eqlog"
	"github.com/Safulet/tss-lib-private/tss"
)

const (
	PathFormat = "TSS-LIB#DeriveKey#EC#%s#SCHEME#%s#CHAINCODE#%s#PATH#%s"
)

func newRound1(params *tss.Parameters, key *LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- tss.Message) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func getHashToCurveInstance(ec elliptic.Curve) (hash2curve.HashToPoint, error) {
	dst := "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
	hashToCurve, err := hash2curve.Secp256k1_XMDSHA256_SSWU_RO_.Get([]byte(dst))
	if err != nil {
		return nil, err
	}
	if tss.SameCurve(ec, tss.Edwards()) {
		dst = "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"
		hashToCurve, err = hash2curve.Edwards25519_XMDSHA512_ELL2_RO_.Get([]byte(dst))
		if err != nil {
			return nil, err
		}
	}
	if tss.SameCurve(ec, tss.Bls12381G2()) {
		dst := "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
		hashToCurve, err = hash2curve.BLS12381G2_XMDSHA256_SSWU_RO_.Get([]byte(dst))
		if err != nil {
			return nil, err
		}
	}
	if tss.SameCurve(ec, tss.P256()) {
		dst := "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
		hashToCurve, err = hash2curve.P256_XMDSHA256_SSWU_RO_.Get([]byte(dst))
		if err != nil {
			return nil, err
		}
	}
	return hashToCurve, nil
}

func getPathString(ec elliptic.Curve, scheme string, pChainCode, path []byte) (string, error) {
	ecName, ok := tss.GetCurveName(ec)
	if !ok {
		return "", errors.New("error get curve name")
	}
	var fullPath = fmt.Sprintf(PathFormat,
		ecName, scheme, string(pChainCode), string(path))
	return fullPath, nil
}

func getH2CPoint(ec elliptic.Curve, hashToCurve hash2curve.HashToPoint, wPath string) (*crypto.ECPoint, error) {
	if tss.SameCurve(tss.Pallas(), ec) {
		curve := curves.PALLAS()
		h2cPoint := curve.Point.Hash([]byte(wPath)).(*curves.PointPallas)
		pointHi, err := crypto.NewECPoint(ec, h2cPoint.X().BigInt(), h2cPoint.Y().BigInt())
		if err != nil {
			return nil, err
		}
		return pointHi, nil
	}
	h2cPoint := hashToCurve.Hash([]byte(wPath))
	h2cPx := h2cPoint.X().Polynomial()[0]
	h2cPy := h2cPoint.Y().Polynomial()[0]
	if tss.SameCurve(tss.Bls12381G2(), ec) {
		h2cPx1 := h2cPoint.X().Polynomial()[0]
		h2cPx2 := h2cPoint.X().Polynomial()[1]
		h2cPy1 := h2cPoint.Y().Polynomial()[0]
		h2cPy2 := h2cPoint.Y().Polynomial()[1]
		xBzs := make([]byte, 96)
		yBzs := make([]byte, 96)
		copy(xBzs[:48], common.PadToLengthBytesInPlace(h2cPx2.Bytes(), 48))
		copy(xBzs[48:], common.PadToLengthBytesInPlace(h2cPx1.Bytes(), 48))
		copy(yBzs[:48], common.PadToLengthBytesInPlace(h2cPy2.Bytes(), 48))
		copy(yBzs[48:], common.PadToLengthBytesInPlace(h2cPy1.Bytes(), 48))
		h2cPx.SetBytes(xBzs)
		h2cPy.SetBytes(yBzs)
	}
	pointHi, err := crypto.NewECPoint(ec, h2cPx, h2cPy)
	if err != nil {
		return nil, err
	}
	return pointHi, nil
}

func (round *round1) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	ssid, err := round.getSSID(ctx)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	round.temp.bssid = new(big.Int).SetBytes(ssid[:])

	hashToCurve, err := getHashToCurveInstance(round.EC())
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	wPath, err := getPathString(round.EC(), "TBD", round.temp.pChainCode, round.temp.path)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	pointHi, err := getH2CPoint(round.EC(), hashToCurve, wPath)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	pointVi := pointHi.ScalarMult(round.temp.wi)
	pointG, err := crypto.NewECPoint(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	proof, err := zkpeqlog.NewProof(ctx, ssid, round.EC(), pointG, pointHi, round.temp.bigWs[i], pointVi, round.temp.wi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	round.temp.pointHi = pointHi
	round.temp.pointVi = pointVi

	// 4. broadcast commitment
	r1msg := NewDeriveKeyRound1Message(round.PartyID(), round.temp.bssid, pointVi.X(), pointVi.Y(), proof)
	round.temp.derivekeyRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.derivekeyRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DeriveKeyRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}

// ----- //

// helper to call into PrepareForDeriveKey()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForDeriveKey(round.Params().EC(), i, len(ks), xi, ks, round.key.BigXj)

	round.temp.wi = wi
	round.temp.bigWs = bigWs
	return nil
}
