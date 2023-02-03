// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package ckd_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	. "github.com/Safulet/tss-lib-private/v2/crypto/ckd"
	"github.com/Safulet/tss-lib-private/v2/eddsa/signing"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestPublicDerivation(t *testing.T) {
	ctx := context.Background()
	// port from https://github.com/btcsuite/btcutil/blob/master/hdkeychain/extendedkey_test.go
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	testVec2MasterPubKey := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewExtendedKeyFromString(test.master, btcec.S256())
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			_, extKey, err = DeriveChildKeyOfEcdsa(ctx, childNum, extKey, btcec.S256())
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		pubStr := extKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Derive #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

func TestEdwards(t *testing.T) {
	ctx := context.Background()
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	privKeyScaler := big.NewInt(667)

	pkExt, err := NewExtendedKeyFromString(testVec1MasterPubKey, tss.S256())
	assert.NoError(t, err)

	ec := tss.Edwards()
	pkNew, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	pkNew = pkNew.ScalarMult(privKeyScaler)
	pkExt.PublicKey = *pkNew

	path := []uint32{0, 1, 2, 2}
	delta, childExtKey, err := DeriveChildKeyFromHierarchy(ctx, path, pkExt, ec.Params().N, ec)
	assert.NoError(t, err)
	assert.False(t, delta.Uint64() == 0, "delta is not zero")
	assert.True(t, childExtKey.PublicKey.IsOnCurve())

	childExtPubKey := edwards.NewPublicKey(childExtKey.PublicKey.X(), childExtKey.PublicKey.Y())

	// checking child key: parent private key + delta -> child private key
	childPrivKeyScaler := new(big.Int).Add(privKeyScaler, delta)
	childPrivKey, childPubKey, err := edwards.PrivKeyFromScalar(signing.CopyBytes(childPrivKeyScaler.Bytes())[:])
	assert.Equal(t, childPubKey.Serialize(), childExtPubKey.Serialize())

	sig, _ := childPrivKey.Sign([]byte("hashedData"))
	verified := ed25519.Verify(childExtPubKey.Serialize(), []byte("hashedData"), sig.Serialize())
	assert.True(t, verified)
}

func Test_DeriveChildPubKeyOfEddsa(t *testing.T) {
	ctx := context.Background()
	// ** Note **
	// the lowest 3 bits of the first byte of seed should be cleared
	// the highest bit of the last byte of seed should be cleared

	masterPrivKeyScalar := big.NewInt(3214213216876)
	masterPrivKey, masterPubKey, err := edwards.PrivKeyFromScalar(signing.CopyBytes(masterPrivKeyScalar.Bytes())[:])
	assert.NoError(t, err)
	message := "secret message"
	sig, _ := masterPrivKey.Sign([]byte(message))
	verified := ed25519.Verify(masterPubKey.Serialize(), []byte(message), sig.Serialize())
	assert.True(t, verified)

	// refer to ** note **
	// privKey.Serialize()[0]  -> xxxx_x000
	// privKey.Serialize()[31] -> 0xxx_xxxx
	fmt.Printf("privKey(%d bytes big endian):    %s\n", len(masterPrivKey.Serialize()), hex.EncodeToString(masterPrivKey.Serialize()))
	fmt.Printf("pubKey(%d bytes little endian):  %s\n", len(masterPubKey.Serialize()), hex.EncodeToString(masterPubKey.Serialize()))

	hx, _ := hex.DecodeString("025939244ddb392ecf98c16439e47ba2de2e3cc7642b628f99dd2998f5c596cf")
	pkEcPoint, err := crypto.NewECPoint(edwards.Edwards(), masterPubKey.X, masterPubKey.Y)
	assert.NoError(t, err)
	extKey := &ExtendedKey{
		PublicKey: *pkEcPoint,
		ChainCode: hx,
	}

	delta := big.NewInt(0)
	mod_ := common.ModInt(edwards.Edwards().N)
	var k = extKey
	for _, childNum := range []uint32{0, 4, 51, 37} {
		var err error
		deltaTmp := delta
		delta, extKey, err = DeriveChildKeyOfEddsa(ctx, childNum, k, edwards.Edwards())
		if err != nil {
			t.Errorf("err: %v", err)
			continue
		}
		k = extKey
		delta = mod_.Add(deltaTmp, delta)
	}

	log.Printf("delta:%s\n", delta.String())

	childPubKeyFromPubBytes := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     extKey.PublicKey.X(),
		Y:     extKey.PublicKey.Y(),
	}.Serialize()

	log.Printf("childPubKeyFromPubBytes:   %x\n", childPubKeyFromPubBytes)

	// #1 child private key = parent private key + delta
	childPrivKeyScalar, _ := EddsaAddPrivKeyScalar(masterPrivKey.Serialize(), delta)
	childPrivKeyFromDelta, _, err := edwards.PrivKeyFromScalar(signing.CopyBytes(childPrivKeyScalar)[:32])
	assert.NoError(t, err)
	log.Printf("childPrivKeyFromDelta:     %x\n", childPrivKeyFromDelta.Serialize())

	hashed := []byte("hashedData")
	sig, _ = childPrivKeyFromDelta.Sign(hashed)
	verified = ed25519.Verify(childPubKeyFromPubBytes, hashed, sig.Serialize())
	assert.True(t, verified)
}

func EddsaAddPrivKeyScalar(privKey []byte, delta *big.Int) ([]byte, error) {
	if delta == nil {
		return privKey, nil
	}

	newPrivKey := big.NewInt(0).Add(big.NewInt(0).SetBytes(privKey), delta)
	newPrivKey = new(big.Int).Mod(newPrivKey, edwards.Edwards().N)

	return newPrivKey.Bytes(), nil
}
