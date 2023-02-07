// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zilsigning

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
	"github.com/roasbeef/btcd/btcec"
)

func ZILSchnorrVerify(pubkey *crypto.ECPoint, msg []byte, signature []byte) error {
	curve := tss.S256()

	if len(signature) < 64 {
		return fmt.Errorf("signature is invalid")
	}

	r := signature[:32]
	s := signature[32:64]
	bintR := new(big.Int).SetBytes(r)
	bintS := new(big.Int).SetBytes(s)

	// cannot be zero
	if bintR.Cmp(big.NewInt(0)) == 0 || bintS.Cmp(big.NewInt(0)) == 0 {
		return fmt.Errorf("invalid R or S value: cannot be zero")
	}

	// cannot be negative
	if bintR.Sign() == -1 || bintS.Sign() == -1 {
		return fmt.Errorf("Invalid R or S value: cannot be negative")
	}

	// cannot be greater than curve.N
	if bintR.Cmp(curve.Params().N) == 1 || bintS.Cmp(curve.Params().N) == 1 {
		return fmt.Errorf("invalid R or S value: cannot be greater than order of secp256k1")
	}

	pkx, pky := pubkey.X(), pubkey.Y()
	lx, ly := curve.ScalarMult(pkx, pky, r)
	rx, ry := curve.ScalarBaseMult(s)
	Qx, Qy := curve.Add(rx, ry, lx, ly)
	Q := secp256k1Compress(Qx, Qy, true)

	pkBytes := secp256k1Compress(pkx, pky, true)
	_r := schnorrHash(Q, pkBytes, msg)
	_rn := new(big.Int).Mod(new(big.Int).SetBytes(_r), curve.Params().N)

	rn := new(big.Int).SetBytes(r)
	if rn.Cmp(_rn) == 0 {
		return nil
	}
	return fmt.Errorf("verify failed")
}

func secp256k1Compress(x, y *big.Int, compress bool) []byte {
	byteLen := (btcec.S256().Params().BitSize + 7) >> 3

	if compress {
		ret := make([]byte, 1+byteLen)
		if y.Bit(0) == 0 {
			ret[0] = 2
		} else {
			ret[0] = 3
		}
		xBytes := x.Bytes()
		copy(ret[1+byteLen-len(xBytes):], xBytes)
		return ret
	}

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point
	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	yBytes := y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)

	return ret
}

func schnorrHash(Q []byte, pubKey []byte, msg []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write(Q)
	buffer.Write(pubKey[:33])
	buffer.Write(msg)

	hash := sha256.New()
	hash.Write(buffer.Bytes())
	return hash.Sum(nil)
}
