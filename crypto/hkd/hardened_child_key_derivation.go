package hkd

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func DeriveChildKeyFromHierarchyForSchnorr(curve elliptic.Curve, pubKey *crypto.ECPoint, delta []byte) (*crypto.ECPoint, error) {
	pk, err := DeriveHardenedChildPublicKey(curve, pubKey, delta)
	if err != nil {
		return nil, err
	}
	if pk.Y().Bit(0) == 1 {
		cPk := pk.Neg()
		pk = cPk
	}
	return pk, err
}

func DeriveHardenedChildPublicKey(curve elliptic.Curve, pubKey *crypto.ECPoint, delta []byte) (*crypto.ECPoint, error) {

	ilNum := new(big.Int).SetBytes(delta)
	var deltaG *crypto.ECPoint
	var childPkX, childPkY *big.Int

	if tss.SameCurve(curve, tss.Edwards()) {
		DeltaX, DeltaY := curve.ScalarBaseMult(delta)
		childPkX, childPkY = curve.Add(pubKey.X(), pubKey.Y(), DeltaX, DeltaY)
	} else {

		if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
			// falling outside the valid range for curve private keys
			return nil, fmt.Errorf("invalid derived key")

		}

		deltaG = crypto.ScalarBaseMult(curve, ilNum)
		if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
			return nil, fmt.Errorf("invalid child")
		}
		childCryptoPk, cpkErr := pubKey.Add(deltaG)
		if cpkErr != nil {
			return nil, cpkErr
		}
		childPkX = childCryptoPk.X()
		childPkY = childCryptoPk.Y()

	}

	cryptoPk, err := crypto.NewECPoint(curve, childPkX, childPkY)
	if err != nil {
		return nil, err
	}

	return cryptoPk, nil
}
