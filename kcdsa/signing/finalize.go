// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/ckd"
	"github.com/Safulet/tss-lib-private/tss"
)

func (round *finalization) VerifySig(ctx context.Context, s *big.Int, e *big.Int, m []byte, pubkey *crypto.ECPoint) bool {
	return verifySig(round.EC(), ctx, s, e, m, pubkey)
}

func VerifySig(ctx context.Context, s *big.Int, e *big.Int, m []byte, pubkey *crypto.ECPoint) bool {
	ec := tss.Curve25519()
	return verifySig(ec, ctx, s, e, m, pubkey)
}

func verifySig(ec elliptic.Curve, ctx context.Context, s *big.Int, e *big.Int, m []byte, pubkey *crypto.ECPoint) bool {
	one := big.NewInt(1)
	N := ec.Params().N
	if s.Cmp(one) < 0 {
		return false
	}
	if s.Cmp(N) >= 0 {
		return false
	}
	if len(e.Bytes()) > 32 {
		return false
	}
	sY := pubkey.ScalarMult(s)
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	eG := g.ScalarMult(e)
	// if y coordinate of pk is even, then eG should negate
	needsNeg := pubkey.Y().Bit(0) == 0
	if needsNeg {
		Y2 := new(big.Int).Sub(ec.Params().P, eG.Y())
		eG2, err := crypto.NewECPoint(ec, eG.X(), Y2)
		if err != nil {
			return false
		}
		eG = eG2
	}

	W, _ := sY.Add(eG)
	mHash := sha256.Sum256(m)
	mHashPkBytes := append(mHash[:], ckd.ReverseBytes(W.X().Bytes())...)
	e2Bytes := sha256.Sum256(mHashPkBytes)

	// e1 == e2
	return e.Cmp(new(big.Int).SetBytes(ckd.ReverseBytes(e2Bytes[:]))) == 0
}

func (round *finalization) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// count k * x
	modN := common.ModInt(new(big.Int).Set(round.EC().Params().N))
	sumKXShare := round.temp.KXShare
	sumBigKxShare := round.temp.BigKXShare
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		var err error
		message := round.temp.signRound5Messages[j].Content().(*SignRound5Message1)
		kxShare := message.UnmarshalKXShare()
		bigKxShare, err := message.UnmarshalBigKXShare(round.EC())
		if err != nil {
			return round.WrapError(errors.New("can not add kx share"))
		}
		proofLogstar, err := message.UnmarshalProofLogstar(round.EC())
		if err != nil {
			return round.WrapError(errors.New("can not get proof log star"))
		}
		ContextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)
		ok := proofLogstar.Verify(ctx, ContextJ, round.EC(), round.key.PaillierPKs[j], round.temp.Ks[j], bigKxShare, round.temp.BigXAll, round.key.PaillierSK.N, round.key.H1i, round.key.H2i)
		if !ok {
			return round.WrapError(errors.New("proof log star verify failed"))
		}

		sumKXShare = modN.Add(sumKXShare, kxShare)
		sumBigKxShare, err = sumBigKxShare.Add(bigKxShare)
		if err != nil {
			return round.WrapError(errors.New("can not add rx share"))
		}
	}
	g := crypto.NewECPointNoCurveCheck(round.EC(), round.EC().Params().Gx, round.EC().Params().Gy)
	bigRXShareCount := g.ScalarMult(sumKXShare)
	if !sumBigKxShare.Equals(bigRXShareCount) {
		return round.WrapError(errors.New("share not equal failed"))
	}

	sBytes := make([]byte, 32)
	sumKXShare.FillBytes(sBytes)
	eBytes := make([]byte, 32)
	round.temp.e.FillBytes(eBytes)

	// save the signature for final output
	round.data.R = ckd.ReverseBytes(sBytes)
	round.data.S = ckd.ReverseBytes(eBytes)
	round.data.Signature = append(round.data.R, round.data.S...)

	round.data.M = round.temp.m

	ok := round.VerifySig(ctx, sumKXShare, round.temp.e, round.temp.m, round.key.PubKey)
	if !ok {
		return round.WrapError(errors.New("signature verification failed"), round.PartyID())
	}

	round.end <- *round.data
	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
