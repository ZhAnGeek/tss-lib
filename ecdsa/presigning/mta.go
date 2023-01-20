// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presigning

import (
	"context"
	"crypto/elliptic"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/paillier"
	zkpaffg "github.com/Safulet/tss-lib-private/crypto/zkp/affg"
)

type MtAOut struct {
	Dji     *big.Int
	Fji     *big.Int
	Sij     *big.Int
	Rij     *big.Int
	Beta    *big.Int
	Proofji *zkpaffg.ProofAffg
}

func NewMtA(ctx context.Context, Session []byte, ec elliptic.Curve, Kj *big.Int, gammai *big.Int, BigGammai *crypto.ECPoint, pkj *paillier.PublicKey, pki *paillier.PublicKey, NCap, s, t *big.Int) (*MtAOut, error) {
	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	betaNeg := common.GetRandomPositiveInt(q3)
	beta := new(big.Int).Sub(q3, betaNeg)

	gammaK, err := pkj.HomoMult(gammai, Kj)
	if err != nil {
		return nil, err
	}
	Dji, sij, err := pkj.EncryptAndReturnRandomness(betaNeg)
	if err != nil {
		return nil, err
	}
	Dji, err = pkj.HomoAdd(gammaK, Dji)
	if err != nil {
		return nil, err
	}

	Fji, rij, err := pki.EncryptAndReturnRandomness(betaNeg)
	if err != nil {
		return nil, err
	}

	Psiji, err := zkpaffg.NewProof(ctx, Session, ec, pkj, pki, NCap, s, t, Kj, Dji, Fji, BigGammai, gammai, betaNeg, sij, rij)
	if err != nil {
		return nil, err
	}

	return &MtAOut{
		Dji:     Dji,
		Fji:     Fji,
		Sij:     sij,
		Rij:     rij,
		Beta:    beta,
		Proofji: Psiji,
	}, nil
}
