// Copyright © 2021 Swingby

package presigning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/ckd"
	"github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/log"
)

func UpdatePublicKeyAndAdjustBigXj(ctx context.Context, keyDerivationDelta *big.Int, keys []keygen.LocalPartySaveData, extendedChildPk *ecdsa.PublicKey, ec elliptic.Curve) error {
	var err error
	gDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	for k := range keys {
		keys[k].ECDSAPub, err = crypto.NewECPoint(ec, extendedChildPk.X, extendedChildPk.Y)
		// keys[k].ECDSAPub, err = keys[k].ECDSAPub.Add(gDelta)
		if err != nil {
			log.Error(ctx, "error creating new extended child public key")
			return err
		}
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				log.Error(ctx, "error in delta operation")
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
			log.Error(ctx, "error creating new extended child public key")
			return err
		}
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				log.Error(ctx, "error in delta operation")
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

	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  *pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		// The version bytes comes from HDPrivateKeyID in
		// https://github.com/btcsuite/btcd/blob/029e5a3cb555f8362d46e05a7310f254d0efcf97/chaincfg/params.go#L424C38-L424C42
		Version: []byte{0x4, 0x88, 0xad, 0xe4},
	}

	return ckd.DeriveChildKeyFromHierarchy(ctx, path, extendedParentPk, ec.Params().N, ec)
}
