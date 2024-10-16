// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package utils

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/ckd"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/v2/schnorr/keygen"
)

func ApplyCkdXAndTweakToOneECDSAKeySave(ec elliptic.Curve, key *ecdsa_keygen.LocalPartySaveData, childDelta *big.Int, tweakInputs []byte) (*ecdsa_keygen.LocalPartySaveData, error) {
	modN := common.ModInt(ec.Params().N)
	// find index
	idx, err := key.OriginalIndex()
	if err != nil {
		return nil, err
	}
	n := len(key.BigXj)

	tweakDelta, finalPK, err := ckd.DeriveTweakedKey(key.ECDSAPub, childDelta, tweakInputs)
	if err != nil {
		return nil, err
	}

	cDelta := crypto.ScalarBaseMult(ec, childDelta)
	cPK, err := key.ECDSAPub.Add(cDelta)
	if err != nil {
		return nil, err
	}
	key.Xi = modN.Add(key.Xi, childDelta)
	for i := 0; i < n; i++ {
		key.BigXj[i], err = key.BigXj[i].Add(cDelta)
		if err != nil {
			return nil, err
		}
	}
	if cPK.Y().Bit(0) == 1 {
		cPK = cPK.Neg()
		key.Xi = modN.Sub(common.Zero, key.Xi)
		for i := 0; i < n; i++ {
			key.BigXj[i] = key.BigXj[i].Neg()
		}
	}
	tDelta := crypto.ScalarBaseMult(ec, tweakDelta)
	dPK, err := cPK.Add(tDelta)
	if err != nil {
		return nil, err
	}
	if !dPK.Equals(finalPK) {
		return nil, err
	}
	key.ECDSAPub = dPK
	key.Xi = modN.Add(key.Xi, tweakDelta)
	for i := 0; i < n; i++ {
		key.BigXj[i], err = key.BigXj[i].Add(tDelta)
		if err != nil {
			return nil, err
		}
	}
	// check x_i * G
	BigXi := crypto.ScalarBaseMult(ec, key.Xi)
	if !BigXi.Equals(key.BigXj[idx]) {
		return nil, errors.New("BigXi not correct")
	}

	return key, nil
}

func ApplyDeltaToECDSALocalPartySaveData(ec elliptic.Curve, threshold int, keys []ecdsa_keygen.LocalPartySaveData, delta *big.Int) ([]ecdsa_keygen.LocalPartySaveData, error) {
	_, scrambler, err := vss.Create(ec, threshold, big.NewInt(0), keys[0].Ks)
	if err != nil {
		return nil, errors.New("create scrambler failed")
	}
	PubKeyDelta := crypto.ScalarBaseMult(ec, delta)
	if PubKeyDelta == nil {
		return nil, errors.New("invalid delta")
	}
	ChildPk, err := PubKeyDelta.Add(keys[0].ECDSAPub)
	if err != nil {
		return nil, err
	}
	modN := common.ModInt(ec.Params().N)
	for i := range keys {
		x := keys[i].LocalSecrets.Xi
		refBigX := crypto.ScalarBaseMult(ec, x)
		if refBigX == nil {
			return nil, errors.New("invalid keystore x")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			Xj := keys[j].BigXj[idx]
			if !Xj.Equals(refBigX) {
				return nil, errors.New("invalid keystore x")
			}
		}
	}
	for i := range keys {
		keys[i].ECDSAPub = ChildPk
		iDelta := delta
		idx, err := keys[i].OriginalIndex()
		if err != nil {
			return nil, err
		}
		iDelta = modN.Add(iDelta, scrambler[idx].Share)
		keys[i].LocalSecrets.Xi = modN.Add(keys[i].LocalSecrets.Xi, iDelta)
		iDeltaG := crypto.ScalarBaseMult(ec, iDelta)
		if iDeltaG == nil {
			return nil, errors.New("invalid delta")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			keys[j].BigXj[idx], err = keys[j].BigXj[idx].Add(iDeltaG)
			if err != nil {
				return nil, err
			}
		}
	}

	for i := range keys {
		xi := keys[i].LocalSecrets.Xi
		refBigXi := crypto.ScalarBaseMult(ec, xi)
		if refBigXi == nil {
			return nil, errors.New("invalid bigXj")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			BigXi := keys[j].BigXj[idx]
			if !refBigXi.Equals(BigXi) {
				fmt.Println("BigXi", BigXi.X(), "ref", refBigXi.X())
				return nil, errors.New("invalid bigXj")
			}
		}
	}

	return keys, nil
}

func ApplyCkdToOneEDDSAKeySave(ec elliptic.Curve, key *eddsa_keygen.LocalPartySaveData, childDelta *big.Int) (*eddsa_keygen.LocalPartySaveData, error) {
	modN := common.ModInt(ec.Params().N)
	// find index
	idx, err := key.OriginalIndex()
	if err != nil {
		return nil, err
	}
	n := len(key.BigXj)

	cDelta := crypto.ScalarBaseMult(ec, childDelta)
	cPK, err := key.PubKey.Add(cDelta)
	if err != nil {
		return nil, err
	}
	key.Xi = modN.Add(key.Xi, childDelta)
	for i := 0; i < n; i++ {
		key.BigXj[i], err = key.BigXj[i].Add(cDelta)
		if err != nil {
			return nil, err
		}
	}
	key.PubKey = cPK
	key.EDDSAPub = cPK

	// check x_i * G
	BigXi := crypto.ScalarBaseMult(ec, key.Xi)
	if !BigXi.Equals(key.BigXj[idx]) {
		return nil, errors.New("BigXi not correct")
	}

	return key, nil
}

func ApplyDeltaToEDDSALocalPartySaveData(ec elliptic.Curve, threshold int, keys []eddsa_keygen.LocalPartySaveData, delta *big.Int) ([]eddsa_keygen.LocalPartySaveData, error) {
	_, scrambler, err := vss.Create(ec, threshold, big.NewInt(0), keys[0].Ks)
	if err != nil {
		return nil, errors.New("create scrambler failed")
	}
	PubKeyDelta := crypto.ScalarBaseMult(ec, delta)
	if PubKeyDelta == nil {
		return nil, errors.New("invalid delta")
	}
	if keys[0].EDDSAPub == nil {
		return nil, errors.New("invalid EDDSAPub")
	}
	ChildPk, err := PubKeyDelta.Add(keys[0].EDDSAPub)
	if err != nil {
		return nil, err
	}
	modN := common.ModInt(ec.Params().N)
	for i := range keys {
		x := new(big.Int).Mod(keys[i].LocalSecrets.Xi, ec.Params().N)
		refBigX := crypto.ScalarBaseMult(ec, x)
		if refBigX == nil {
			return nil, errors.New("invalid keystore x")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			Xj := keys[j].BigXj[idx]
			if !Xj.Equals(refBigX) {
				return nil, errors.New("invalid keystore x")
			}
		}
	}
	for i := range keys {
		keys[i].EDDSAPub = ChildPk
		keys[i].PubKey = ChildPk
		iDelta := delta
		idx, err := keys[i].OriginalIndex()
		if err != nil {
			return nil, err
		}
		iDelta = modN.Add(iDelta, scrambler[idx].Share)
		keys[i].LocalSecrets.Xi = modN.Add(keys[i].LocalSecrets.Xi, iDelta)
		iDeltaG := crypto.ScalarBaseMult(ec, iDelta)
		if iDeltaG == nil {
			return nil, errors.New("invalid delta")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			keys[j].BigXj[idx], err = keys[j].BigXj[idx].Add(iDeltaG)
			if err != nil {
				return nil, err
			}
		}
	}

	for i := range keys {
		xi := keys[i].LocalSecrets.Xi
		refBigXi := crypto.ScalarBaseMult(ec, xi)
		if refBigXi == nil {
			return nil, errors.New("invalid bigXj")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			BigXi := keys[j].BigXj[idx]
			if !refBigXi.Equals(BigXi) {
				fmt.Println("BigXi", BigXi.X(), "ref", refBigXi.X())
				return nil, errors.New("invalid bigXj")
			}
		}
	}

	return keys, nil
}

func ApplyDeltaToSchnorrLocalPartySaveData(ec elliptic.Curve, threshold int, keys []schnorr_keygen.LocalPartySaveData, delta *big.Int) ([]schnorr_keygen.LocalPartySaveData, error) {
	_, scrambler, err := vss.Create(ec, threshold, big.NewInt(0), keys[0].Ks)
	if err != nil {
		return nil, errors.New("create scrambler failed")
	}
	PubKeyDelta := crypto.ScalarBaseMult(ec, delta)
	if PubKeyDelta == nil {
		return nil, errors.New("invalid delta")
	}
	if keys[0].PubKey == nil {
		return nil, errors.New("invalid EDDSAPub")
	}
	ChildPk, err := PubKeyDelta.Add(keys[0].PubKey)
	if err != nil {
		return nil, err
	}
	modN := common.ModInt(ec.Params().N)
	for i := range keys {
		x := keys[i].LocalSecrets.Xi
		refBigX := crypto.ScalarBaseMult(ec, x)
		if refBigX == nil {
			return nil, errors.New("invalid keystore x")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			Xj := keys[j].BigXj[idx]
			if !Xj.Equals(refBigX) {
				return nil, errors.New("invalid keystore x")
			}
		}
	}
	for i := range keys {
		keys[i].PubKey = ChildPk
		iDelta := delta
		idx, err := keys[i].OriginalIndex()
		if err != nil {
			return nil, err
		}
		iDelta = modN.Add(iDelta, scrambler[idx].Share)
		keys[i].LocalSecrets.Xi = modN.Add(keys[i].LocalSecrets.Xi, iDelta)
		iDeltaG := crypto.ScalarBaseMult(ec, iDelta)
		if iDeltaG == nil {
			return nil, errors.New("invalid delta")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			keys[j].BigXj[idx], err = keys[j].BigXj[idx].Add(iDeltaG)
			if err != nil {
				return nil, err
			}
		}
	}

	for i := range keys {
		xi := keys[i].LocalSecrets.Xi
		refBigXi := crypto.ScalarBaseMult(ec, xi)
		if refBigXi == nil {
			return nil, errors.New("invalid bigXj")
		}
		for j := range keys {
			idx, err := keys[i].OriginalIndex()
			if err != nil {
				return nil, err
			}
			BigXi := keys[j].BigXj[idx]
			if !refBigXi.Equals(BigXi) {
				fmt.Println("BigXi", BigXi.X(), "ref", refBigXi.X())
				return nil, errors.New("invalid bigXj")
			}
		}
	}

	return keys, nil
}
