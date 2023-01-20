// Copyright © 2021 Swingby

package presigning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/ckd"
	"github.com/Safulet/tss-lib-private/ecdsa/keygen"

	"github.com/btcsuite/btcd/chaincfg"
)

func UpdatePublicKeyAndAdjustBigXj(ctx context.Context, keyDerivationDelta *big.Int, keys []keygen.LocalPartySaveData, extendedChildPk *ecdsa.PublicKey, ec elliptic.Curve) error {
	var err error
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	for k := range keys {
		keys[k].ECDSAPub, err = crypto.NewECPoint(ec, extendedChildPk.X, extendedChildPk.Y)
		// keys[k].ECDSAPub, err = keys[k].ECDSAPub.Add(gDelta)
		if err != nil {
			common.Logger.Errorf("error creating new extended child public key")
			return err
		}
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error in delta operation")
				return err
			}
		}
	}
	return nil
}

func UpdateKeys(ctx context.Context, keyDerivationDelta *big.Int, keys []keygen.LocalPartySaveData, extendedChildPk *ecdsa.PublicKey, ec elliptic.Curve) error {
	var err error
	modN := common.ModInt(ec.Params().N)
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	for k := range keys {
		keys[k].Xi = modN.Add(keys[k].Xi, keyDerivationDelta)
		keys[k].ECDSAPub, err = crypto.NewECPoint(ec, extendedChildPk.X, extendedChildPk.Y)
		// keys[k].ECDSAPub, err = keys[k].ECDSAPub.Add(gDelta)
		if err != nil {
			common.Logger.Errorf("error creating new extended child public key")
			return err
		}
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error in delta operation")
				return err
			}
		}
	}
	return nil
}

func DerivingPubkeyFromPath(ctx context.Context, masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk, err := crypto.NewECPoint(ec, masterPub.X(), masterPub.Y())
	if err != nil {
		return nil, nil, err
	}

	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  *pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	return ckd.DeriveChildKeyFromHierarchy(ctx, path, extendedParentPk, ec.Params().N, ec)
}
