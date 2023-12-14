// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package btc

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/tss"

	"github.com/Safulet/tss-lib-private/crypto"
)

const (
	// scalarSize is the size of an encoded big endian scalar.
	scalarSize = 32
)

var (
	TagNonce     = "BIP0340/nonce"
	TagChallenge = "BIP0340/challenge"
)

// SchnorrVerify attempt to verify the signature for the provided hash and
// secp256k1 public key and either returns nil if successful or a specific error
// indicating why it failed if not successful.
//
// This differs from the exported Verify method in that it returns a specific
// error to support better testing while the exported method simply returns a
// bool indicating success or failure.
func SchnorrVerify(ec elliptic.Curve, pubKey *crypto.ECPoint, msg, sig []byte) error {
	// The algorithm for producing a BIP-340 signature is described in
	// README.md and is reproduced here for reference:
	//
	// 1. Fail if m is not 32 bytes
	// 2. P = lift_x(int(pk)).
	// 3. r = int(sig[0:32]); fail is r >= p.
	// 4. s = int(sig[32:64]); fail if s >= n.
	// 5. e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	// 6. R = s*G - e*P
	// 7. Fail if is_infinite(R)
	// 8. Fail if not hash_even_y(R)
	// 9. Fail is x(R) != r.
	// 10. Return success iff not failure occured before reachign this
	// point.
	if !tss.SameCurve(ec, tss.S256()) || !tss.SameCurve(ec, pubKey.Curve()) {
		str := "signing curve is different than tss.S256()"
		return errors.New(str)
	}

	// Step 1.
	//
	// Fail if m is not 32 bytes
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return errors.New(str)
	}

	// Step 2.
	//
	// P = lift_x(int(pk))
	//
	// Fail if P is not a point on the curve
	if !pubKey.IsOnCurve() {
		str := "pubkey point is not on curve"
		return errors.New(str)
	}

	r := sig[:32]
	s := sig[32:64]
	iR := new(big.Int).SetBytes(r)
	iS := new(big.Int).SetBytes(s)
	// Step 3.
	//
	// Fail if r >= p
	//
	if iR.Cmp(big.NewInt(0)) == 0 {
		return errors.New("invalid R value: cannot be zero")
	}
	if iR.Sign() == -1 {
		return errors.New("invalid R value: cannot be negative")
	}
	if iR.Cmp(ec.Params().P) >= 0 {
		return errors.New("invalid R value: must be smaller than P")
	}

	// Step 4.
	//
	// Fail if s >= n
	//
	if iS.Cmp(big.NewInt(0)) == 0 {
		return errors.New("invalid S value: cannot be zero")
	}
	if iS.Sign() == -1 {
		return errors.New("invalid S value: cannot be negative")
	}
	if iS.Cmp(ec.Params().N) >= 0 {
		return errors.New("invalid S value: must be smaller than N")
	}

	// Step 5.
	//
	// e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	// Negate e here so we can use AddNonConst below to subtract the s*G
	// point from e*P.
	// e.Negate()
	pkx := pubKey.X()
	e_ := common.TaggedHash256([]byte(TagChallenge), r, common.PadToLengthBytesInPlace(pkx.Bytes(), 32), msg)
	e := new(big.Int).Mod(new(big.Int).SetBytes(e_), ec.Params().N)
	e = new(big.Int).Sub(ec.Params().N, e)

	// Step 6.
	//
	// R = s*G - e*P
	sG := crypto.ScalarBaseMult(ec, iS)
	neP := pubKey.ScalarMult(e)
	R, err := sG.Add(neP)
	if err != nil {
		return err
	}

	// Step 7.
	//
	// Fail if R is the point at infinity
	if R.X() == nil || R.Y() == nil {
		return errors.New("R is the point at infinity")
	}

	// Step 8.
	//
	// Fail if R.y is odd
	//
	// Note that R must be in affine coordinates for this check.
	if R.Y().Bit(0) == 1 {
		str := "calculated R y-value is odd"
		return errors.New(str)
	}

	// Step 9.
	//
	// Verified if R.x == r
	//
	// Note that R must be in affine coordinates for this check.
	if iR.Cmp(R.X()) != 0 {
		str := "calculated R point was not given R"
		return errors.New(str)
	}

	// Step 10.
	//
	// Return success iff not failure occured before reachign this
	return nil
}
