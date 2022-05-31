// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package ckd_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/binance-chain/tss-lib/crypto"
	. "github.com/binance-chain/tss-lib/crypto/ckd"
	"github.com/binance-chain/tss-lib/eddsa/signing"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestPublicDerivation(t *testing.T) {
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
			_, extKey, err = DeriveChildKey(childNum, extKey, btcec.S256())
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
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	privKeyScaler := big.NewInt(667)

	pkExt, err := NewExtendedKeyFromString(testVec1MasterPubKey, tss.S256())
	assert.NoError(t, err)

	ec := tss.Edwards()
	pkNew, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	pkNew = pkNew.ScalarMult(privKeyScaler)
	pkExt.PublicKey = *pkNew

	path := []uint32{0, 1, 2, 2}
	delta, childExtKey, err := DeriveChildKeyFromHierarchy(path, pkExt, ec.Params().N, ec)
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

func TestEdwardsDeriveChildPrivateKey(t *testing.T) {

	pubBytes, _ := hex.DecodeString("5e6f105657c7e35e2110fbfd9c2c2a48fb5ea3ff8e0d7672323754960400c4ef")
	privKey, pubKey := edwards.PrivKeyFromBytes(append([]byte("helloworldhelloworldhelloworldab"), pubBytes...))

	message := "secret message"
	sig, _ := privKey.Sign([]byte(message))
	verified := ed25519.Verify(pubKey.Serialize(), []byte(message), sig.Serialize())
	assert.True(t, verified)

	assert.NotNil(t, privKey)
	assert.NotNil(t, pubKey)
	fmt.Printf("privKey(%d bytes): %s\n", len(privKey.Serialize()), hex.EncodeToString(privKey.Serialize()))
	fmt.Printf("pubKey(%d bytes):  %s\n", len(pubKey.Serialize()), hex.EncodeToString(pubKey.Serialize()))
	// message := "secret message"

	hx, _ := hex.DecodeString("025939244ddb392ecf98c16439e47ba2de2e3cc7642b628f99dd2998f5c596cf")
	pkEcPoint, err := crypto.NewECPoint(edwards.Edwards(), pubKey.X, pubKey.Y)
	assert.NoError(t, err)
	extKey := &ExtendedKey{
		PublicKey: *pkEcPoint,
		ChainCode: hx,
	}

	var delta *big.Int
	var childPrivKey []byte
	var extPubKey *ExtendedKey
	var childPubKey *ecdsa.PublicKey
	for _, childNum := range []uint32{0} {
		var err error
		delta, extPubKey, err = DeriveChildPubKeyOfEddsa(childNum, extKey)
		if err != nil {
			t.Errorf("err: %v", err)
			continue
		}
		childPrivKey, childPubKey, _, err = DeriveChildPrivateKeyOfEddsa(childNum, extKey.ChainCode, privKey)
		if err != nil {
			t.Errorf("err: %v", err)
			continue
		}
	}

	log.Printf("delta:%s\n", delta.String())
	log.Printf("extKeyPriv: %x %x\n", childPrivKey[:32], childPrivKey[32:])

	childPubKeyFromPubBytes := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     extPubKey.PublicKey.X(),
		Y:     extPubKey.PublicKey.Y(),
	}.Serialize()

	childPubKeyFromPrivBytes := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     childPubKey.X,
		Y:     childPubKey.Y,
	}.Serialize()

	log.Printf("childPubKeyFromPubBytes:   %x\n", childPubKeyFromPubBytes)
	log.Printf("childPubKeyFromPrivBytes:  %x\n", childPubKeyFromPrivBytes)

	childPrivKeyDelta := AddPrivKeyScalar(privKey.GetD(), delta, edwards.Edwards())
	fmt.Printf("deltaChildPrivKey: %x\n", childPrivKeyDelta)

	childPrivKeyFromDelta, _, err := edwards.PrivKeyFromScalar(childPrivKeyDelta.Bytes())
	assert.NoError(t, err)
	// log.Printf("childPrivKey:   %x\n", childPrivKey.Serialize())
	// log.Printf("childPubKey:    %x\n", childPubKey.Serialize())

	sig, _ = childPrivKeyFromDelta.Sign([]byte(message))
	verified = ed25519.Verify(childPubKeyFromPrivBytes, []byte(message), sig.Serialize())

	assert.True(t, verified)

}
