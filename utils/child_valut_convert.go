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
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/v2/schnorr/keygen"
)

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
