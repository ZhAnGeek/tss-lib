// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mina

import (
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
	"github.com/coinbase/kryptology/pkg/signatures/schnorr/mina"
)

func MinaSchnorrVerify(pubkey *crypto.ECPoint, msg []byte, signature []byte) error {
	if len(signature) < 64 {
		return fmt.Errorf("signature is invalid")
	}
	curve := tss.Pallas()

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	// cannot be zero
	if r.Cmp(big.NewInt(0)) == 0 || s.Cmp(big.NewInt(0)) == 0 {
		return fmt.Errorf("invalid R or S value: cannot be zero")
	}

	// cannot be negative
	if r.Sign() == -1 || s.Sign() == -1 {
		return fmt.Errorf("Invalid R or S value: cannot be negative")
	}

	// must be smaller than curve.N
	if r.Cmp(curve.Params().P) >= 0 || s.Cmp(curve.Params().N) >= 0 {
		return fmt.Errorf("invalid R or S value: must be smaller than order of secp256k1")
	}

	e := SchnorrHash(r, pubkey, msg)

	sg := new(curves.Ep).Generator()
	sg.Mul(sg, new(fq.Fq).SetBigInt(s))

	epk := new(curves.Ep).Mul(getEP(pubkey), new(fq.Fq).SetBigInt(new(big.Int).SetBytes(e)))
	epk.Neg(epk)

	rc := new(curves.Ep).Add(sg, epk)
	if rc.IsOnCurve() && !rc.Y().IsOdd() && rc.X().Equal(new(fp.Fp).SetBigInt(r)) {
		return nil
	}
	return fmt.Errorf("verify failed")
}

func getEP(pubKey *crypto.ECPoint) *curves.Ep {
	xb := new(fp.Fp).SetBigInt(pubKey.X()).Bytes()
	yb := new(fp.Fp).SetBigInt(pubKey.Y()).Bytes()
	p, err := new(curves.Ep).FromAffineUncompressed(append(xb[:], yb[:]...))
	if err != nil {
		panic(err)
	}
	return p
}

func SchnorrHash(r *big.Int, pubKey *crypto.ECPoint, msg []byte) []byte {
	networkId := mina.NetworkType(mina.MainNet)
	input := new(Roinput)
	if len(msg) > 0 && input.RecoverRaw(msg[1:]) == nil {
		networkId = mina.NetworkType(msg[0])
	} else {
		input.Init(0, len(msg))
		input.AddBytes(msg)
	}

	pkx := new(fp.Fp).SetBigInt(pubKey.X())
	pky := new(fp.Fp).SetBigInt(pubKey.Y())
	rx := new(fp.Fp).SetBigInt(r)

	input.AddFp(pkx)
	input.AddFp(pky)
	input.AddFp(rx)
	ctx := new(mina.Context).Init(mina.ThreeW, networkId)
	fields := input.Fields()
	ctx.Update(fields)
	return ctx.Digest().BigInt().Bytes()
}
