// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/eddsa/keygen"
	kcdsa_keygen "github.com/Safulet/tss-lib-private/kcdsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/schnorr/keygen"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type RestoredPrivateKey struct {
	curve elliptic.Curve // the curve
	sk    *big.Int       // the raw private key value
}

func NewRestoredPrivateKey(ec elliptic.Curve, sk *big.Int) *RestoredPrivateKey {
	return &RestoredPrivateKey{
		curve: ec,
		sk:    sk,
	}
}

func (rpk *RestoredPrivateKey) ToECDSAPriv() (*ecdsa.PrivateKey, error) {
	privBz := rpk.sk.Bytes() // output is big endian
	expectLen := btcec.PrivKeyBytesLen

	if len(privBz) > expectLen {
		return nil, errors.New("sk bytes more than 32")
	}
	if len(privBz) < expectLen {
		privBz = common.PadToLengthBytesInPlace(privBz, expectLen)
	}

	if len(privBz) != expectLen { // impossible
		return nil, errors.New("invalid private key length")
	}

	privKey, _ := btcec.PrivKeyFromBytes(privBz) // privBz is big-endian

	return privKey.ToECDSA(), nil
}

func (rpk *RestoredPrivateKey) ToEdwardsPriv() (*edwards.PrivateKey, error) {
	privBz := rpk.sk.Bytes() // golang output big-endian
	expectLen := edwards.PrivScalarSize
	if len(privBz) != expectLen {
		privBz = common.PadToLengthBytesInPlace(privBz, expectLen)
	}
	edPriv, _, err := edwards.PrivKeyFromScalar(privBz)
	if err != nil {
		return nil, err
	}

	return edPriv, nil
}

func (rpk *RestoredPrivateKey) SK() *big.Int {
	return rpk.sk
}

func RestoreECDSAPrivateKey(ec elliptic.Curve, threshold int, keys []ecdsa_keygen.LocalPartySaveData) (*RestoredPrivateKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys length must larger than 0")
	}

	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: threshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	if err != nil {
		return nil, fmt.Errorf("ReConstruct failed: %v", err)
	}

	pub := crypto.ScalarBaseMult(ec, sk)
	if !pub.Equals(keys[0].ECDSAPub) {
		return nil, errors.New("pubkey derived from sk should equal pk")
	}

	return NewRestoredPrivateKey(ec, sk), nil
}

func RestoreEDDSAPrivateKey(ec elliptic.Curve, threshold int, keys []eddsa_keygen.LocalPartySaveData) (*RestoredPrivateKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys length must larger than 0")
	}

	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: threshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	if err != nil {
		return nil, err
	}

	pub := crypto.ScalarBaseMult(ec, sk)
	if !pub.Equals(keys[0].EDDSAPub) {
		return nil, errors.New("pubkey derived from sk should equal pk")
	}
	return NewRestoredPrivateKey(ec, sk), nil
}

func RestoreKCDSAPrivateKey(ec elliptic.Curve, threshold int, keys []kcdsa_keygen.LocalPartySaveData) (*RestoredPrivateKey, error) {
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: threshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	if err != nil {
		return nil, errors.New("reconstruct should not fail")
	}

	pub := crypto.ScalarBaseMult(ec, new(big.Int).ModInverse(sk, ec.Params().N))
	if pub.X().Cmp(keys[0].PubKey.X()) != 0 {
		return nil, errors.New("pubkey derived from sk should equal pk")
	}

	return NewRestoredPrivateKey(ec, sk), nil
}

func RestoreSchnorrPrivate(ec elliptic.Curve, threshold int, keys []schnorr_keygen.LocalPartySaveData) (*RestoredPrivateKey, error) {
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: threshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	if err != nil {
		return nil, errors.New("reconstruct should not fail")
	}

	pub := crypto.ScalarBaseMult(ec, sk)

	if !pub.Equals(keys[0].PubKey) {
		return nil, errors.New("pubkey derived from sk should equal pk")
	}

	return NewRestoredPrivateKey(ec, sk), nil
}
