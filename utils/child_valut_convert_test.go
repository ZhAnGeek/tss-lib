// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/ckd"
	"github.com/Safulet/tss-lib-private/v2/crypto/edwards25519"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/v2/schnorr/keygen"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/stretchr/testify/assert"
)

func TestConvertECDSAKeyShare(t *testing.T) {
	ec := tss.S256()

	keys, _, err := ecdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreECDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	privKey, err := restoredPriv.ToECDSAPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].ECDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := &privKey.PublicKey
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))

	assert.True(t, rawPub.Equal(priPub))

	for i := 0; i < len(keys); i++ {
		result, err := ApplyCkdXAndTweakToOneECDSAKeySave(ec, &keys[i], big.NewInt(123), []byte{1, 2, 3})
		assert.NoError(t, err)
		keys[i] = *result
	}

	restoredPriv, err = RestoreECDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	refPK := crypto.ScalarBaseMult(ec, restoredPriv.sk)
	assert.True(t, refPK.Equals(keys[0].ECDSAPub))
	fmt.Println("refPK:", refPK.X().String())
	fmt.Println("actPK:", keys[0].ECDSAPub.X().String())

}

func TestConvertEDDSAKeyShare(t *testing.T) {
	ec := tss.Edwards()

	keys, _, err := eddsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreEDDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	privKey, err := restoredPriv.ToEdwardsPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].EDDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := privKey.PubKey().ToECDSA()
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))
	assert.True(t, rawPub.Equal(priPub))

	for i := 0; i < len(keys); i++ {
		result, err := ApplyCkdToOneEDDSAKeySave(ec, &keys[i], big.NewInt(123))
		assert.NoError(t, err)
		keys[i] = *result
	}

	restoredPriv, err = RestoreEDDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())
	refPK := crypto.ScalarBaseMult(ec, restoredPriv.sk)
	assert.True(t, refPK.Equals(keys[0].PubKey))
	fmt.Println("refPK:", refPK.X().String())
	fmt.Println("actPK:", keys[0].PubKey.X().String())
}

func TestConvertECDSAKeyStore(t *testing.T) {
	ec := tss.S256()

	keys, _, err := ecdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreECDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	privKey, err := restoredPriv.ToECDSAPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].ECDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := &privKey.PublicKey
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))

	assert.True(t, rawPub.Equal(priPub))

	// test Ks too big
	for i := range keys {
		for j := range keys[i].Ks {
			keys[i].Ks[j] = new(big.Int).Add(keys[i].Ks[j], ec.Params().N)
		}
		keys[i].ShareID = new(big.Int).Add(keys[i].ShareID, ec.Params().N)
	}
	keys, err = ApplyDeltaToECDSALocalPartySaveData(ec, test.TestThreshold, keys, big.NewInt(999))
	assert.NoError(t, err)
	restoredPriv, err = RestoreECDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())
}

func TestConvertEDDSAKeyStore(t *testing.T) {
	ec := tss.Edwards()

	keys, _, err := eddsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreEDDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())
	fmt.Println("PK.X:", keys[0].PubKey.X())
	fmt.Println("PK.Y:", keys[0].PubKey.Y())

	privKey, err := restoredPriv.ToEdwardsPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].EDDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := privKey.PubKey().ToECDSA()
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))
	assert.True(t, rawPub.Equal(priPub))

	masterPrivKeyScalar := restoredPriv.sk
	masterPrivKeyBytes := common.PadToLengthBytesInPlace(masterPrivKeyScalar.Bytes(), 32)
	masterPubKeyX, masterPubKeyY := ec.ScalarBaseMult(masterPrivKeyScalar.Bytes())
	masterPubKeyBytes := edwards25519.EcPointToEncodedBytes(masterPubKeyX, masterPubKeyY)[:]
	fmt.Printf("privKey(%d bytes big endian):    %s\n", len(masterPrivKeyBytes), hex.EncodeToString(masterPrivKeyBytes))
	fmt.Printf("pubKey(%d bytes little endian):  %s\n", len(masterPubKeyBytes), hex.EncodeToString(masterPubKeyBytes))

	hx, _ := hex.DecodeString("025939244ddb392ecf98c16439e47ba2de2e3cc7642b628f99dd2998f5c596cf")
	pkEcPoint, err := crypto.NewECPoint(ec, masterPubKeyX, masterPubKeyY)
	assert.NoError(t, err)
	extKey := &ckd.ExtendedKey{
		PublicKey: *pkEcPoint,
		ChainCode: hx,
	}
	path := []uint32{1, 2, 3, 4}
	ctx := context.Background()
	delta, childExtKey, err := ckd.DeriveChildKeyFromHierarchy(ctx, path, extKey, ec.Params().N, ec)
	fmt.Println("delta:", delta)
	fmt.Println("derived cPK.X:", childExtKey.PublicKey.X())
	fmt.Println("derived cPK.Y:", childExtKey.PublicKey.Y())

	// test Ks too big
	for i := range keys {
		for j := range keys[i].Ks {
			keys[i].Ks[j] = new(big.Int).Add(keys[i].Ks[j], ec.Params().N)
		}
		keys[i].ShareID = new(big.Int).Add(keys[i].ShareID, ec.Params().N)
	}
	keys, err = ApplyDeltaToEDDSALocalPartySaveData(ec, test.TestThreshold, keys, delta)
	assert.NoError(t, err)
	restoredPriv, err = RestoreEDDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	fmt.Println("output PK.X:", keys[0].PubKey.X())
	fmt.Println("output PK.Y:", keys[0].PubKey.Y())
	assert.True(t, childExtKey.PublicKey.Equals(keys[0].PubKey))
	assert.True(t, childExtKey.PublicKey.Equals(keys[0].EDDSAPub))
	assert.True(t, childExtKey.PublicKey.Equals(keys[1].PubKey))
	assert.True(t, childExtKey.PublicKey.Equals(keys[1].EDDSAPub))

}

func TestConvertSchnorrS256KeyStore(t *testing.T) {
	ec := tss.S256()

	keys, _, err := schnorr_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreSchnorrPrivate(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())

	privKey, err := restoredPriv.ToECDSAPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].PubKey.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := &privKey.PublicKey
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))
	assert.True(t, rawPub.Equal(priPub))

	// test Ks too big
	for i := range keys {
		for j := range keys[i].Ks {
			keys[i].Ks[j] = new(big.Int).Add(keys[i].Ks[j], ec.Params().N)
		}
		keys[i].ShareID = new(big.Int).Add(keys[i].ShareID, ec.Params().N)
	}
	keys, err = ApplyDeltaToSchnorrLocalPartySaveData(ec, test.TestThreshold, keys, big.NewInt(999))
	assert.NoError(t, err)
	restoredPriv, err = RestoreSchnorrPrivate(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	fmt.Println("restoredPriv", restoredPriv.sk.String())
}
