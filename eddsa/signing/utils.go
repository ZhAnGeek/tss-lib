// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/subtle"
	"hash"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/edwards25519"
	"github.com/Safulet/tss-lib-private/tss"
)

// VerifyEdwards verifies a message 'hash' using the given public keys and signature.
// func VerifyEdwards(pub *edwards.PublicKey, msg []byte, r, s *big.Int, hashFunc func() hash.Hash) bool {
func VerifyEdwards(pub *crypto.ECPoint, msg []byte, r, s *big.Int, hashFunc func() hash.Hash) bool {
	if pub == nil || msg == nil || r == nil || s == nil {
		return false
	}

	pubBytes := edwards25519.EcPointToEncodedBytes(pub.X(), pub.Y())
	sigBytes := append(edwards25519.BigIntToEncodedBytes(r)[:], edwards25519.BigIntToEncodedBytes(s)[:]...)

	if sigBytes[63]&224 != 0 {
		return false
	}

	ec := tss.Edwards()
	negX := new(big.Int).Sub(ec.Params().P, pub.X())

	h := hashFunc()
	h.Reset()
	h.Write(sigBytes[:32])
	h.Write(pubBytes[:])
	h.Write(msg)
	var digest [64]byte
	h.Sum(digest[:0])

	hReduced := new(big.Int).Mod(new(big.Int).SetBytes(common.ReverseBytes(digest[:])), ec.Params().N)
	retX, retY := ec.ScalarMult(negX, pub.Y(), hReduced.Bytes())
	tmpX, tmpY := ec.ScalarBaseMult(s.Bytes())
	retX, retY = ec.Add(retX, retY, tmpX, tmpY)

	encodedR := edwards25519.EcPointToEncodedBytes(retX, retY)
	ok := subtle.ConstantTimeCompare(encodedR[:], sigBytes[:32]) == 1

	return ok
}
