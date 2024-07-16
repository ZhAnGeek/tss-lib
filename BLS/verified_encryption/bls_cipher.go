// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package verified_encryption

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/BLS/encryption"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func BLSEncryptionAndReturnRandomness(ec elliptic.Curve, pk *crypto.ECPoint, message []byte) (encryption.EncryptedData, []byte, []byte, *big.Int, error) {
	var totalPK, suite []byte
	if tss.SameCurve(ec, tss.Bls12381G2()) {
		suite = bls12381.GetBLSSignatureSuiteG1()
		totalPK = make([]byte, 192)
		pk.X().FillBytes(totalPK[:96])
		pk.Y().FillBytes(totalPK[96:])
	} else if tss.SameCurve(ec, tss.Bls12381G1()) {
		suite = bls12381.GetBLSSignatureSuiteG2()
		totalPK = make([]byte, 96)
		pk.X().FillBytes(totalPK[:48])
		pk.Y().FillBytes(totalPK[48:])
	} else {
		return encryption.EncryptedData{}, nil, nil, nil, errors.New("curve is not supported")
	}

	encryptedResult, aesKey, iv, r, err := bls12381.EncryptAndReturnRandomness(suite, totalPK, message)

	if err != nil {
		return encryption.EncryptedData{}, nil, nil, nil, err
	}

	return encryption.EncryptedData{CipherText: encryptedResult}, aesKey, iv, r, nil
}

func BLSEncryptionWithRandomness(ec elliptic.Curve, pk *crypto.ECPoint, message, aesKey, iv []byte, r *big.Int) (encryption.EncryptedData, error) {
	var totalPK, suite []byte
	if tss.SameCurve(ec, tss.Bls12381G2()) {
		suite = bls12381.GetBLSSignatureSuiteG1()
		totalPK = make([]byte, 192)
		pk.X().FillBytes(totalPK[:96])
		pk.Y().FillBytes(totalPK[96:])
	} else if tss.SameCurve(ec, tss.Bls12381G1()) {
		suite = bls12381.GetBLSSignatureSuiteG2()
		totalPK = make([]byte, 96)
		pk.X().FillBytes(totalPK[:48])
		pk.Y().FillBytes(totalPK[48:])
	} else {
		return encryption.EncryptedData{}, errors.New("curve is not supported")
	}

	encryptedResult, err := bls12381.EncryptWithRandomness(suite, totalPK, message, aesKey, iv, r)

	if err != nil {
		return encryption.EncryptedData{}, err
	}

	return encryption.EncryptedData{CipherText: encryptedResult}, nil
}
